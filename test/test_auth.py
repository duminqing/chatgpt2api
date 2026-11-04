from __future__ import annotations

import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.accounts as accounts_module
import api.support as support_module
import api.system as system_module
import services.auth_service as auth_module
from services.auth_service import AuthService, SESSION_TTL_SECONDS
from services.storage.database_storage import DatabaseStorageBackend
from services.storage.json_storage import JSONStorageBackend


ADMIN_KEY = "test-admin-key"
PASSWORD = " Example密码123 "


def headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class MemoryStorage:
    def __init__(self):
        self.items = []

    def load_auth_keys(self):
        return copy.deepcopy(self.items)

    def save_auth_keys(self, items):
        self.items = copy.deepcopy(items)


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.storage = MemoryStorage()
        self.service = AuthService(self.storage)
        fake_config = SimpleNamespace(
            auth_key=ADMIN_KEY,
            get=lambda: {"setting": "admin-only"},
            get_third_party_apps_settings=lambda: {"infinite_canvas": {"enabled": False, "url": ""}},
        )
        for patcher in [
            mock.patch.object(auth_module, "config", fake_config),
            mock.patch.object(support_module, "config", fake_config),
            mock.patch.object(support_module, "auth_service", self.service),
            mock.patch.object(system_module, "config", fake_config),
            mock.patch.object(system_module, "auth_service", self.service),
            mock.patch.object(accounts_module, "auth_service", self.service),
        ]:
            patcher.start()
            self.addCleanup(patcher.stop)
        app = FastAPI()
        app.include_router(system_module.create_router("test-version"))
        app.include_router(accounts_module.create_router())
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.user, self.user_key = self.service.create_key(role="user", name="测试用户")

    def bind(self, key=ADMIN_KEY, username="admin.user", password=PASSWORD):
        response = self.client.post("/auth/credentials", headers=headers(key), json={"username": username, "password": password})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def password_login(self, username="admin.user", password=PASSWORD):
        return self.client.post("/auth/password-login", json={"username": username, "password": password})

    def session(self, username="admin.user", password=PASSWORD):
        response = self.password_login(username, password)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["session_token"]

    def test_existing_keys_work_without_binding_or_default_password(self):
        for key, role in [(ADMIN_KEY, "admin"), (self.user_key, "user")]:
            response = self.client.post("/auth/login", headers=headers(key), json={})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["role"], role)
            self.assertEqual(self.client.get("/auth/credentials", headers=headers(key)).json(), {"username": "", "configured": False})
        self.assertEqual(self.password_login().status_code, 401)
        self.assertEqual(len(self.storage.items), 1)

    def test_credentials_require_authentication(self):
        for method in (self.client.get, self.client.post, self.client.delete):
            kwargs = {"json": {"username": "attacker", "password": PASSWORD}} if method == self.client.post else {}
            self.assertEqual(method("/auth/credentials", **kwargs).status_code, 401)

    def test_admin_can_bind_and_use_both_login_methods(self):
        self.assertEqual(self.bind(), {"username": "admin.user", "configured": True})
        token = self.session("ADMIN.USER")
        identity = self.client.post("/auth/login", headers=headers(token)).json()
        self.assertEqual((identity["role"], identity["subject_id"]), ("admin", "admin"))
        for key in (token, ADMIN_KEY):
            self.assertEqual(self.client.get("/api/settings", headers=headers(key)).status_code, 200)

    def test_user_can_only_bind_own_identity_and_keeps_user_role(self):
        response = self.client.post("/auth/credentials", headers=headers(self.user_key), json={
            "username": "regular.user", "password": PASSWORD, "id": "admin", "role": "admin",
        })
        self.assertEqual(response.status_code, 200)
        token = self.session("regular.user")
        identity = self.client.post("/auth/login", headers=headers(token)).json()
        self.assertEqual((identity["role"], identity["subject_id"]), ("user", self.user["id"]))
        self.assertEqual(self.client.get("/api/settings", headers=headers(token)).status_code, 403)
        self.assertEqual(self.client.get("/api/auth/users", headers=headers(token)).status_code, 403)
        self.assertEqual(self.client.get("/auth/credentials", headers=headers(ADMIN_KEY)).json()["configured"], False)
        self.assertEqual(self.client.post("/auth/login", headers=headers(self.user_key)).status_code, 200)

    def test_passwords_and_session_tokens_are_only_stored_as_hashes(self):
        self.bind()
        token = self.session()
        serialized = json.dumps(self.storage.items, ensure_ascii=False)
        self.assertNotIn(PASSWORD, serialized)
        self.assertNotIn(token, serialized)
        stored_admin = next(item for item in self.storage.items if item["id"] == "admin")
        self.assertTrue(stored_admin["password_hash"].startswith("pbkdf2_sha256$600000$"))
        public = json.dumps(self.service.list_keys())
        self.assertNotIn("password_hash", public)
        self.assertNotIn("key_hash", public)
        self.assertNotIn("sessions", public)

    def test_each_password_uses_a_different_random_salt(self):
        self.bind()
        self.bind(self.user_key, "regular.user")
        self.assertEqual(len({item["password_hash"] for item in self.storage.items}), 2)

    def test_usernames_are_unique_case_insensitively_across_roles(self):
        self.bind()
        response = self.client.post("/auth/credentials", headers=headers(self.user_key), json={"username": "ADMIN.USER", "password": PASSWORD})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.get("/auth/credentials", headers=headers(self.user_key)).json()["configured"], False)

    def test_credentials_validation(self):
        for username, password in [("ab", PASSWORD), ("has spaces", PASSWORD), ("valid", "short"), ("valid", "x" * 1025)]:
            with self.subTest(username=username, password_length=len(password)):
                response = self.client.post("/auth/credentials", headers=headers(ADMIN_KEY), json={"username": username, "password": password})
                self.assertIn(response.status_code, (400, 422))
        self.assertEqual(self.storage.items[0].get("password_hash", ""), "")

    def test_wrong_password_unknown_and_disabled_user_have_same_error(self):
        self.bind(self.user_key, "regular.user")
        wrong = self.password_login("regular.user", "wrong-password")
        missing = self.password_login("missing.user")
        trimmed = self.password_login("regular.user", PASSWORD.strip())
        self.service.update_key(str(self.user["id"]), {"enabled": False})
        disabled = self.password_login("regular.user")
        for response in (wrong, missing, trimmed, disabled):
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json(), wrong.json())

    def test_password_change_revokes_sessions_but_preserves_key(self):
        self.bind()
        token = self.session()
        self.bind(ADMIN_KEY, "admin.renamed", "new-password-123")
        self.assertEqual(self.client.post("/auth/login", headers=headers(token)).status_code, 401)
        self.assertEqual(self.password_login().status_code, 401)
        self.assertEqual(self.password_login("admin.renamed", "new-password-123").status_code, 200)
        self.assertEqual(self.client.post("/auth/login", headers=headers(ADMIN_KEY)).status_code, 200)

    def test_password_change_from_session_requires_relogin(self):
        self.bind()
        token = self.session()
        self.bind(token, "admin.user", "new-password-123")
        self.assertEqual(self.client.post("/auth/login", headers=headers(token)).status_code, 401)
        self.assertEqual(self.password_login(password="new-password-123").status_code, 200)

    def test_optional_login_can_be_removed_and_key_still_works(self):
        for key, username in [(ADMIN_KEY, "admin.user"), (self.user_key, "regular.user")]:
            self.bind(key, username)
            token = self.session(username)
            response = self.client.delete("/auth/credentials", headers=headers(token))
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json()["configured"])
            self.assertEqual(self.client.post("/auth/login", headers=headers(token)).status_code, 401)
            self.assertEqual(self.password_login(username).status_code, 401)
            self.assertEqual(self.client.post("/auth/login", headers=headers(key)).status_code, 200)

    def test_logout_revokes_only_current_session_and_never_api_key(self):
        self.bind(self.user_key, "regular.user")
        first, second = self.session("regular.user"), self.session("regular.user")
        self.assertEqual(self.client.post("/auth/logout", headers=headers(first)).status_code, 200)
        self.assertIsNone(self.service.authenticate(first))
        self.assertIsNotNone(self.service.authenticate(second))
        self.client.post("/auth/logout", headers=headers(self.user_key))
        self.assertIsNotNone(self.service.authenticate(self.user_key))

    def test_expired_session_is_rejected_after_restart(self):
        self.bind()
        token = self.session()
        restarted = AuthService(self.storage)
        self.assertIsNotNone(restarted.authenticate(token))
        with mock.patch.object(auth_module.time, "time", return_value=time.time() + SESSION_TTL_SECONDS + 1):
            self.assertIsNone(restarted.authenticate(token))

    def test_malformed_sessions_do_not_break_existing_key_authentication(self):
        for sessions in (123, "invalid", [None, {}, {"key_hash": "非哈希", "expires_at": float("inf")}]):
            with self.subTest(sessions=sessions):
                self.storage.items[0]["sessions"] = sessions
                self.assertIsNotNone(self.service.authenticate(self.user_key))

    def test_disabling_or_deleting_user_revokes_sessions_across_instances(self):
        self.bind(self.user_key, "regular.user")
        token = self.session("regular.user")
        other = AuthService(self.storage)
        self.assertIsNotNone(other.authenticate(token))
        self.service.update_key(str(self.user["id"]), {"enabled": False})
        self.assertIsNone(other.authenticate(token))
        self.service.update_key(str(self.user["id"]), {"enabled": True})
        self.assertIsNone(other.authenticate(token))
        token = self.session("regular.user")
        self.service.delete_key(str(self.user["id"]))
        self.assertIsNone(other.authenticate(token))
        self.assertEqual(self.password_login("regular.user").status_code, 401)

    def test_rotating_user_key_revokes_sessions_and_preserves_password_login(self):
        self.bind(self.user_key, "regular.user")
        token = self.session("regular.user")
        self.service.update_key(str(self.user["id"]), {"key": "replacement-user-key"})
        self.assertIsNone(self.service.authenticate(self.user_key))
        self.assertIsNone(self.service.authenticate(token))
        self.assertIsNotNone(self.service.authenticate("replacement-user-key"))
        self.assertEqual(self.password_login("regular.user").status_code, 200)

    def test_login_attempts_are_limited_and_expire(self):
        for _ in range(10):
            self.assertEqual(self.password_login().status_code, 401)
        response = self.password_login()
        self.assertEqual(response.status_code, 429)
        self.assertGreater(int(response.headers["Retry-After"]), 0)
        with mock.patch.object(auth_module.time, "monotonic", return_value=time.monotonic() + 301):
            self.assertEqual(self.password_login().status_code, 401)

    def test_successful_login_resets_failed_attempt_count(self):
        self.bind()
        for _ in range(3):
            self.assertEqual(self.password_login(password="incorrect").status_code, 401)
        self.assertEqual(self.password_login().status_code, 200)
        self.assertEqual(self.service._login_attempts, {})

    def test_session_count_is_bounded(self):
        self.bind()
        tokens = [self.session() for _ in range(11)]
        self.assertIsNone(self.service.authenticate(tokens[0]))
        for token in tokens[1:]:
            self.assertIsNotNone(self.service.authenticate(token))

    def test_login_rechecks_account_if_password_changes_during_verification(self):
        self.bind(self.user_key, "regular.user")
        verify = auth_module._verify_password

        def change_while_verifying(password, encoded):
            self.service.remove_login_credentials(str(self.user["id"]))
            return verify(password, encoded)

        with mock.patch.object(auth_module, "_verify_password", side_effect=change_while_verifying):
            self.assertEqual(self.password_login("regular.user").status_code, 401)

    def test_credentials_and_sessions_persist_with_json_and_sqlite(self):
        with tempfile.TemporaryDirectory() as directory:
            for backend in [
                JSONStorageBackend(Path(directory) / "accounts.json"),
                DatabaseStorageBackend(f"sqlite:///{Path(directory) / 'auth.sqlite'}"),
            ]:
                with self.subTest(backend=type(backend).__name__):
                    service = AuthService(backend)
                    service.set_login_credentials({"id": "admin", "role": "admin"}, "persisted.admin", PASSWORD)
                    login = AuthService(backend).login_with_password("persisted.admin", PASSWORD, "test-client")
                    self.assertIsNotNone(login)
                    self.assertEqual(AuthService(backend).authenticate(login[1])["role"], "admin")
                    service.remove_login_credentials("admin")
                    self.assertIsNone(AuthService(backend).authenticate(login[1]))
                if isinstance(backend, DatabaseStorageBackend):
                    backend.engine.dispose()


if __name__ == "__main__":
    unittest.main()
