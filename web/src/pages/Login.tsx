import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { ErrorNote } from "@/components/ui/state";

export function Login({ onSuccess }: { onSuccess: () => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");

  const m = useMutation({
    mutationFn: () => api.post("/auth/login", { username, password }),
    onSuccess,
  });

  return (
    <div className="bg-background flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-2">
          <div className="bg-primary text-primary-foreground grid size-8 place-items-center rounded-md">
            <ShieldCheck className="size-4" />
          </div>
          <div>
            <div className="font-semibold">CertPilot</div>
            <div className="text-muted-foreground text-xs">证书自动化平台</div>
          </div>
        </div>

        <form
          className="bg-card flex flex-col gap-4 rounded-lg border p-5 shadow-xs"
          onSubmit={(e) => {
            e.preventDefault();
            m.mutate();
          }}
        >
          <Field label="用户名">
            <Input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
          </Field>
          <Field label="密码" hint="初始密码在 api 容器的启动日志里，只显示一次。">
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </Field>

          {m.error && <ErrorNote error={m.error} />}

          <Button type="submit" disabled={m.isPending}>
            {m.isPending ? "登录中…" : "登录"}
          </Button>
        </form>

        <p className="text-muted-foreground mt-4 text-center text-xs">
          这个后台持有全站证书私钥与云账号密钥，请勿直接暴露在公网。
        </p>
      </div>
    </div>
  );
}
