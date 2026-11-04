"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { LoaderCircle, LockKeyhole } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { HeaderActions } from "@/components/header-actions";
import { login, loginWithPassword } from "@/lib/api";
import { useRedirectIfAuthenticated } from "@/lib/use-auth-guard";
import { getDefaultRouteForRole, setStoredAuthSession } from "@/store/auth";

export default function LoginPage() {
  const router = useRouter();
  const [authKey, setAuthKey] = useState("");
  const [loginMethod, setLoginMethod] = useState("key");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { isCheckingAuth } = useRedirectIfAuthenticated();

  const handleLogin = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (isSubmitting) return;
    const normalizedAuthKey = authKey.trim();
    if (loginMethod === "key" ? !normalizedAuthKey : !username.trim() || !password) {
      toast.error(loginMethod === "key" ? "请输入密钥" : "请输入用户名和密码");
      return;
    }

    setIsSubmitting(true);
    try {
      const data = loginMethod === "key"
        ? await login(normalizedAuthKey)
        : await loginWithPassword(username, password);
      await setStoredAuthSession({
        key: "session_token" in data ? String(data.session_token) : normalizedAuthKey,
        role: data.role,
        subjectId: data.subject_id,
        name: data.name,
      });
      router.replace(getDefaultRouteForRole(data.role));
    } catch (error) {
      const message = error instanceof Error ? error.message : "登录失败";
      toast.error(message);
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isCheckingAuth) {
    return (
      <div className="grid min-h-[calc(100vh-1rem)] w-full place-items-center px-4 py-6">
        <LoaderCircle className="size-5 animate-spin text-stone-400" />
      </div>
    );
  }

  return (
    <div className="grid min-h-[calc(100vh-1rem)] w-full place-items-center px-4 py-6">
      <HeaderActions className="fixed top-4 right-4 z-10" />
      <Card className="w-full max-w-[505px] rounded-[30px] border-white/80 bg-white/95 shadow-[0_28px_90px_rgba(28,25,23,0.10)]">
        <CardContent className="space-y-7 p-6 sm:p-8">
          <div className="space-y-4 text-center">
            <div className="mx-auto inline-flex size-14 items-center justify-center rounded-[18px] bg-stone-950 text-white shadow-sm">
              <LockKeyhole className="size-5" />
            </div>
            <div className="space-y-2">
              <h1 className="text-3xl font-semibold tracking-tight text-stone-950">欢迎回来</h1>
              <p className="text-sm leading-6 text-stone-500">使用密钥或已绑定的账号密码登录。</p>
            </div>
          </div>

          <Tabs value={loginMethod} onValueChange={setLoginMethod} className="gap-5">
            <TabsList className="w-full">
              <TabsTrigger value="key" className="flex-1" disabled={isSubmitting}>密钥登录</TabsTrigger>
              <TabsTrigger value="password" className="flex-1" disabled={isSubmitting}>账号密码登录</TabsTrigger>
            </TabsList>
            <form onSubmit={handleLogin} className="space-y-5">
              <TabsContent value="key" className="space-y-3">
                <label htmlFor="auth-key" className="block text-sm font-medium text-stone-700">密钥</label>
                <Input
                  id="auth-key"
                  type="password"
                  value={authKey}
                  onChange={(event) => setAuthKey(event.target.value)}
                  autoComplete="off"
                  required
                  disabled={isSubmitting}
                  placeholder="请输入密钥"
                  className="h-13 rounded-2xl border-stone-200 bg-white px-4"
                />
              </TabsContent>
              <TabsContent value="password" className="space-y-4">
                <div className="space-y-2">
                  <label htmlFor="login-username" className="block text-sm font-medium text-stone-700">用户名</label>
                  <Input
                    id="login-username" name="username" autoComplete="username" required maxLength={64}
                    value={username} onChange={(event) => setUsername(event.target.value)} disabled={isSubmitting}
                    placeholder="请输入用户名" className="h-13 rounded-2xl border-stone-200 bg-white px-4"
                  />
                </div>
                <div className="space-y-2">
                  <label htmlFor="login-password" className="block text-sm font-medium text-stone-700">密码</label>
                  <Input
                    id="login-password" name="password" type="password" autoComplete="current-password" required maxLength={1024}
                    value={password} onChange={(event) => setPassword(event.target.value)} disabled={isSubmitting}
                    placeholder="请输入密码" className="h-13 rounded-2xl border-stone-200 bg-white px-4"
                  />
                </div>
                <p className="text-xs leading-5 text-stone-500">首次使用请先用密钥登录，再在「账户设置」中绑定账号密码（可选）。</p>
              </TabsContent>
              <Button
                className="h-13 w-full rounded-2xl bg-stone-950 text-white hover:bg-stone-800"
                type="submit"
                disabled={isSubmitting}
              >
                {isSubmitting ? <LoaderCircle className="size-4 animate-spin" /> : null}
                登录
              </Button>
            </form>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}
