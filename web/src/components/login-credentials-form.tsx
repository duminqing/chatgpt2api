"use client";

import { useEffect, useId, useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { LoaderCircle } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { fetchLoginCredentials, removeLoginCredentials, saveLoginCredentials } from "@/lib/api";
import { getValidatedAuthSession } from "@/lib/auth-session";

export function LoginCredentialsForm() {
  const router = useRouter();
  const formId = useId();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [configured, setConfigured] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    let active = true;
    fetchLoginCredentials().then((data) => {
      if (active) {
        setUsername(data.username);
        setConfigured(data.configured);
      }
    }).catch((error: unknown) => {
      if (active) setLoadError(error instanceof Error ? error.message : "加载登录账号失败");
    }).finally(() => {
      if (active) setIsLoading(false);
    });
    return () => { active = false; };
  }, []);

  const handleSave = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (isSaving) return;
    if (password !== confirmation) {
      toast.error("两次输入的密码不一致");
      return;
    }
    setIsSaving(true);
    try {
      const data = await saveLoginCredentials(username, password);
      setUsername(data.username);
      setConfigured(data.configured);
      setPassword("");
      setConfirmation("");
      toast.success("登录账号已保存，密钥仍可继续使用");
      if (!await getValidatedAuthSession()) router.replace("/login");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "保存登录账号失败");
    } finally {
      setIsSaving(false);
    }
  };

  const handleRemove = async () => {
    if (isSaving) return;
    setIsSaving(true);
    try {
      await removeLoginCredentials();
      setUsername("");
      setPassword("");
      setConfirmation("");
      setConfigured(false);
      toast.success("已关闭账号密码登录，可继续使用原有密钥登录");
      if (!await getValidatedAuthSession()) router.replace("/login");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "关闭账号密码登录失败");
    } finally {
      setIsSaving(false);
    }
  };

  if (isLoading) return <div className="flex justify-center py-6"><LoaderCircle className="size-5 animate-spin text-stone-400" /></div>;
  if (loadError) return <p role="alert" className="text-sm text-rose-600">{loadError}</p>;

  return (
    <form onSubmit={handleSave} className="space-y-4">
      <p className="text-sm leading-6 text-stone-500">账号密码登录为可选项，绑定或关闭后，原有密钥都可以继续使用。当前{configured ? "已开启" : "未开启"}账号密码登录。</p>
      <div className="space-y-2">
        <label htmlFor={`${formId}-username`} className="text-sm font-medium text-stone-700">用户名</label>
        <Input id={`${formId}-username`} name="username" autoComplete="username" required minLength={3} maxLength={64}
          pattern="[A-Za-z0-9_.@\-]{3,64}" value={username} onChange={(event) => setUsername(event.target.value)}
          disabled={isSaving} placeholder="3–64 位字母、数字或 _ . @ -" className="h-11 rounded-xl" />
      </div>
      <div className="space-y-2">
        <label htmlFor={`${formId}-password`} className="text-sm font-medium text-stone-700">{configured ? "新密码" : "密码"}</label>
        <Input id={`${formId}-password`} name="password" type="password" autoComplete="new-password" required minLength={8} maxLength={1024}
          value={password} onChange={(event) => setPassword(event.target.value)} disabled={isSaving}
          placeholder="至少 8 位，区分大小写" className="h-11 rounded-xl" />
      </div>
      <div className="space-y-2">
        <label htmlFor={`${formId}-confirmation`} className="text-sm font-medium text-stone-700">确认密码</label>
        <Input id={`${formId}-confirmation`} name="confirmation" type="password" autoComplete="new-password" required minLength={8} maxLength={1024}
          value={confirmation} onChange={(event) => setConfirmation(event.target.value)} disabled={isSaving}
          placeholder="再次输入密码" className="h-11 rounded-xl" />
      </div>
      <p className="text-xs leading-5 text-stone-500">修改或关闭后，已有的账号密码登录会话会失效。忘记密码时，可使用原有密钥登录后重新设置。</p>
      <div className="flex flex-wrap justify-end gap-2">
        {configured ? <Button type="button" variant="outline" disabled={isSaving} onClick={() => void handleRemove()}>关闭账号密码登录</Button> : null}
        <Button type="submit" disabled={isSaving}>
          {isSaving ? <LoaderCircle className="size-4 animate-spin" /> : null}
          {configured ? "保存修改" : "绑定账号密码"}
        </Button>
      </div>
    </form>
  );
}
