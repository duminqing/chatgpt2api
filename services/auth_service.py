from __future__ import annotations

import hashlib
import hmac
import math
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from threading import Lock
from typing import Literal

from services.config import config
from services.storage.base import StorageBackend

AuthRole = Literal["admin", "user"]
SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
PASSWORD_ITERATIONS = 600_000
_DUMMY_PASSWORD_HASH = f"pbkdf2_sha256${PASSWORD_ITERATIONS}${'0' * 32}${'0' * 64}"


class LoginRateLimitError(Exception):
    def __init__(self, retry_after: int):
        super().__init__("登录尝试过于频繁，请稍后重试")
        self.retry_after = retry_after


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt}${digest.hex()}"


def _verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$")
        if algorithm != "pbkdf2_sha256" or int(iterations) != PASSWORD_ITERATIONS:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), PASSWORD_ITERATIONS)
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, UnicodeError):
        return False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class AuthService:
    def __init__(self, storage: StorageBackend):
        self.storage = storage
        self._lock = Lock()
        self._items = self._load()
        self._last_used_flush_at: dict[str, datetime] = {}
        self._login_attempts: dict[str, list[float]] = {}

    @staticmethod
    def _clean(value: object) -> str:
        return str(value or "").strip()

    @staticmethod
    def _default_name(role: object) -> str:
        return "管理员密钥" if str(role or "").strip().lower() == "admin" else "普通用户"

    def _normalize_item(self, raw: object) -> dict[str, object] | None:
        if not isinstance(raw, dict):
            return None
        role = self._clean(raw.get("role")).lower()
        if role not in {"admin", "user"}:
            return None
        key_hash = self._clean(raw.get("key_hash"))
        username = self._clean(raw.get("username"))
        password_hash = self._clean(raw.get("password_hash"))
        if not key_hash and not (username and password_hash):
            return None
        item_id = self._clean(raw.get("id")) or uuid.uuid4().hex[:12]
        name = self._clean(raw.get("name")) or self._default_name(role)
        created_at = self._clean(raw.get("created_at")) or _now_iso()
        last_used_at = self._clean(raw.get("last_used_at")) or None
        sessions = raw.get("sessions")
        if not isinstance(sessions, list):
            sessions = []
        return {
            "id": item_id,
            "name": name,
            "role": role,
            "key_hash": key_hash,
            "username": username,
            "password_hash": password_hash,
            "sessions": [
                {"key_hash": session["key_hash"], "expires_at": session["expires_at"]}
                for session in sessions
                if isinstance(session, dict)
                and isinstance(session.get("key_hash"), str)
                and re.fullmatch(r"[0-9a-f]{64}", session["key_hash"])
                and isinstance(session.get("expires_at"), (int, float))
                and math.isfinite(session["expires_at"])
                and session["expires_at"] > time.time()
            ][-10:],
            "enabled": bool(raw.get("enabled", True)),
            "created_at": created_at,
            "last_used_at": last_used_at,
        }

    def _load(self) -> list[dict[str, object]]:
        try:
            items = self.storage.load_auth_keys()
        except Exception:
            return []
        if not isinstance(items, list):
            return []
        return [normalized for item in items if (normalized := self._normalize_item(item)) is not None]

    def _save(self) -> None:
        self.storage.save_auth_keys(self._items)

    def _reload_locked(self) -> None:
        self._items = self._load()

    @staticmethod
    def _public_item(item: dict[str, object]) -> dict[str, object]:
        return {
            "id": item.get("id"),
            "name": item.get("name"),
            "role": item.get("role"),
            "enabled": bool(item.get("enabled", True)),
            "created_at": item.get("created_at"),
            "last_used_at": item.get("last_used_at"),
            "username": item.get("username") or "",
            "has_password": bool(item.get("username") and item.get("password_hash")),
        }

    def list_keys(self, role: AuthRole | None = None) -> list[dict[str, object]]:
        with self._lock:
            self._reload_locked()
            items = [item for item in self._items if role is None or item.get("role") == role]
            return [self._public_item(item) for item in items]

    def _has_key_hash_locked(self, key_hash: str, *, exclude_id: str = "") -> bool:
        for item in self._items:
            item_id = self._clean(item.get("id"))
            if exclude_id and item_id == exclude_id:
                continue
            stored_hash = self._clean(item.get("key_hash"))
            if stored_hash and hmac.compare_digest(stored_hash, key_hash):
                return True
        return False

    def _build_key_hash_locked(self, raw_key: str, *, exclude_id: str = "") -> str:
        candidate = self._clean(raw_key)
        if not candidate:
            raise ValueError("请输入新的专用密钥")
        admin_key = self._clean(config.auth_key)
        if admin_key and hmac.compare_digest(candidate, admin_key):
            raise ValueError("这个密钥和管理员密钥冲突了，请换一个新的密钥")
        key_hash = _hash_key(candidate)
        if self._has_key_hash_locked(key_hash, exclude_id=exclude_id):
            raise ValueError("这个专用密钥已经存在，请换一个新的密钥")
        return key_hash

    def _has_name_locked(self, name: str, *, role: AuthRole | None = None, exclude_id: str = "") -> bool:
        candidate = self._clean(name)
        if not candidate:
            return False
        for item in self._items:
            item_id = self._clean(item.get("id"))
            if exclude_id and item_id == exclude_id:
                continue
            if role is not None and item.get("role") != role:
                continue
            if self._clean(item.get("name")) == candidate:
                return True
        return False

    def _build_default_name_locked(self, role: AuthRole, *, exclude_id: str = "") -> str:
        base_name = self._default_name(role)
        if not self._has_name_locked(base_name, role=role, exclude_id=exclude_id):
            return base_name
        suffix = 2
        while True:
            candidate = f"{base_name} {suffix}"
            if not self._has_name_locked(candidate, role=role, exclude_id=exclude_id):
                return candidate
            suffix += 1

    def _build_name_locked(self, name: str, *, role: AuthRole, exclude_id: str = "") -> str:
        candidate = self._clean(name)
        if not candidate:
            return self._build_default_name_locked(role, exclude_id=exclude_id)
        if self._has_name_locked(candidate, role=role, exclude_id=exclude_id):
            raise ValueError("这个名称已经在使用中了，换一个更容易区分的名称吧")
        return candidate

    def create_key(self, *, role: AuthRole, name: str = "") -> tuple[dict[str, object], str]:
        with self._lock:
            self._reload_locked()
            normalized_name = self._build_name_locked(name, role=role)
            while True:
                raw_key = f"sk-{secrets.token_urlsafe(24)}"
                try:
                    key_hash = self._build_key_hash_locked(raw_key)
                    break
                except ValueError:
                    continue
            item = {
                "id": uuid.uuid4().hex[:12],
                "name": normalized_name,
                "role": role,
                "key_hash": key_hash,
                "enabled": True,
                "created_at": _now_iso(),
                "last_used_at": None,
            }
            self._items.append(item)
            self._save()
            return self._public_item(item), raw_key

    def update_key(
        self,
        key_id: str,
        updates: dict[str, object],
        *,
        role: AuthRole | None = None,
    ) -> dict[str, object] | None:
        normalized_id = self._clean(key_id)
        if not normalized_id:
            return None
        with self._lock:
            self._reload_locked()
            for index, item in enumerate(self._items):
                if item.get("id") != normalized_id:
                    continue
                if role is not None and item.get("role") != role:
                    return None
                next_item = dict(item)
                next_role = "admin" if str(next_item.get("role") or "").strip().lower() == "admin" else "user"
                if "name" in updates and updates.get("name") is not None:
                    next_item["name"] = self._build_name_locked(
                        str(updates.get("name") or ""),
                        role=next_role,
                        exclude_id=normalized_id,
                    )
                if "enabled" in updates and updates.get("enabled") is not None:
                    next_item["enabled"] = bool(updates.get("enabled"))
                if "key" in updates and updates.get("key") is not None:
                    next_item["key_hash"] = self._build_key_hash_locked(str(updates.get("key") or ""), exclude_id=normalized_id)
                    next_item["sessions"] = []
                if not next_item.get("enabled", True):
                    next_item["sessions"] = []
                self._items[index] = next_item
                self._save()
                return self._public_item(next_item)
        return None

    def delete_key(self, key_id: str, *, role: AuthRole | None = None) -> bool:
        normalized_id = self._clean(key_id)
        if not normalized_id:
            return False
        with self._lock:
            self._reload_locked()
            before = len(self._items)
            self._items = [
                item
                for item in self._items
                if not (item.get("id") == normalized_id and (role is None or item.get("role") == role))
            ]
            if len(self._items) == before:
                return False
            self._save()
            return True

    def authenticate(self, raw_key: str) -> dict[str, object] | None:
        candidate = self._clean(raw_key)
        if not candidate:
            return None
        candidate_hash = _hash_key(candidate)
        with self._lock:
            self._reload_locked()
            for index, item in enumerate(self._items):
                if not bool(item.get("enabled", True)):
                    continue
                stored_hash = self._clean(item.get("key_hash"))
                key_matches = bool(stored_hash and hmac.compare_digest(stored_hash, candidate_hash))
                session_matches = any(
                    hmac.compare_digest(session["key_hash"], candidate_hash)
                    for session in item.get("sessions", [])
                )
                if not key_matches and not session_matches:
                    continue
                next_item = dict(item)
                now = datetime.now(timezone.utc)
                next_item["last_used_at"] = now.isoformat()
                self._items[index] = next_item
                item_id = self._clean(next_item.get("id"))
                last_flush_at = self._last_used_flush_at.get(item_id)
                if last_flush_at is None or (now - last_flush_at).total_seconds() >= 60:
                    try:
                        self._save()
                        self._last_used_flush_at[item_id] = now
                    except Exception:
                        pass
                return self._public_item(next_item)
        return None

    def get_login_credentials(self, subject_id: str) -> dict[str, object]:
        with self._lock:
            self._reload_locked()
            item = next((item for item in self._items if item["id"] == subject_id), {})
            return {
                "username": item.get("username") or "",
                "configured": bool(item.get("username") and item.get("password_hash")),
            }

    def set_login_credentials(self, identity: dict[str, object], username: str, password: str) -> dict[str, object]:
        username = username.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,64}", username):
            raise ValueError("用户名需为 3–64 位字母、数字或 _ . @ -")
        if not 8 <= len(password) <= 1024:
            raise ValueError("密码长度需为 8–1024 位")
        subject_id = str(identity["id"])
        password_hash = _hash_password(password)
        with self._lock:
            self._reload_locked()
            if any(
                self._clean(item.get("username")).casefold() == username.casefold() and item["id"] != subject_id
                for item in self._items
            ):
                raise ValueError("这个用户名已被使用，请换一个用户名")
            item = next((item for item in self._items if item["id"] == subject_id), None)
            if item is None:
                if subject_id != "admin" or identity.get("role") != "admin":
                    raise ValueError("当前用户已不存在，请重新登录")
                # The configured administrator key has a stable identity but no stored key record.
                item = {
                    "id": "admin", "name": "管理员", "role": "admin", "key_hash": "",
                    "enabled": True, "created_at": _now_iso(), "last_used_at": None,
                }
                self._items.append(item)
            if not item.get("enabled", True) or item["role"] != identity.get("role"):
                raise ValueError("当前用户已失效，请重新登录")
            item.update(username=username, password_hash=password_hash, sessions=[])
            self._save()
        return {"username": username, "configured": True}

    def remove_login_credentials(self, subject_id: str) -> None:
        with self._lock:
            self._reload_locked()
            for item in self._items:
                if item["id"] == subject_id:
                    item.update(username="", password_hash="", sessions=[])
            self._items = [item for item in self._items if item.get("key_hash") or item.get("password_hash")]
            self._save()

    def login_with_password(self, username: str, password: str, client_id: str) -> tuple[dict[str, object], str] | None:
        now = time.monotonic()
        with self._lock:
            self._login_attempts = {
                key: [stamp for stamp in stamps if now - stamp < 300]
                for key, stamps in self._login_attempts.items()
                if stamps and now - stamps[-1] < 300
            }
            attempts = self._login_attempts.setdefault(client_id, [])
            if len(attempts) >= 10:
                raise LoginRateLimitError(max(1, math.ceil(300 - (now - attempts[0]))))
            attempts.append(now)
            if len(self._login_attempts) > 4096:
                self._login_attempts.pop(next(iter(self._login_attempts)))
            self._reload_locked()
            item = next((
                dict(item) for item in self._items
                if self._clean(item.get("username")).casefold() == username.strip().casefold()
                and item.get("password_hash") and item.get("enabled", True)
            ), None)
        password_hash = str(item["password_hash"]) if item else _DUMMY_PASSWORD_HASH
        valid = _verify_password(password, password_hash)
        if not valid or item is None:
            return None
        raw_session = f"session-{secrets.token_urlsafe(32)}"
        with self._lock:
            self._reload_locked()
            current = next((current for current in self._items if current["id"] == item["id"]), None)
            # Verification runs outside the lock; recheck before issuing a session.
            if (
                current is None or not current.get("enabled", True)
                or current.get("password_hash") != password_hash
                or current.get("username") != item.get("username")
            ):
                return None
            sessions = list(current.get("sessions", []))[-9:]
            sessions.append({"key_hash": _hash_key(raw_session), "expires_at": time.time() + SESSION_TTL_SECONDS})
            current.update(sessions=sessions, last_used_at=_now_iso())
            self._save()
            self._login_attempts.pop(client_id, None)
            return self._public_item(current), raw_session

    def logout(self, raw_session: str) -> None:
        session_hash = _hash_key(raw_session)
        with self._lock:
            self._reload_locked()
            changed = False
            for item in self._items:
                sessions = item.get("sessions", [])
                remaining = [session for session in sessions if not hmac.compare_digest(session["key_hash"], session_hash)]
                if len(remaining) != len(sessions):
                    item["sessions"] = remaining
                    changed = True
            if changed:
                self._save()


auth_service = AuthService(config.get_storage_backend())
