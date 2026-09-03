import { useCallback, useEffect, useState } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider, useQueryClient } from "@tanstack/react-query";
import { api, setUnauthorizedHandler } from "@/lib/api";
import { Login } from "@/pages/Login";
import { Loading } from "@/components/ui/state";
import { Shell } from "@/components/layout/shell";
import { Dashboard } from "@/pages/Dashboard";
import { Certificates } from "@/pages/Certificates";
import { CertificateDetail } from "@/pages/CertificateDetail";
import { Credentials } from "@/pages/Credentials";
import { Targets } from "@/pages/Targets";
import { Servers } from "@/pages/Servers";
import { Health } from "@/pages/Health";
import { Notifications } from "@/pages/Notifications";
import { JobDetail, Jobs } from "@/pages/Jobs";
import { Settings } from "@/pages/Settings";

const qc = new QueryClient({
  defaultOptions: {
    queries: {
      // 运维后台上一个自己乱跳的表格会让人不敢操作：
      // 不做自动轮询，需要刷新时由 WebSocket 事件精确失效对应查询。
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 10_000,
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <Gate />
    </QueryClientProvider>
  );
}

interface Me {
  username: string;
  role: string;
}

/** 登录门禁：未登录只渲染登录页，登录后才挂载整个后台。 */
function Gate() {
  const queryClient = useQueryClient();
  const [me, setMe] = useState<Me | null>(null);
  const [checking, setChecking] = useState(true);

  const check = useCallback(async () => {
    try {
      setMe(await api.get<Me>("/auth/me"));
    } catch {
      setMe(null);
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    // 任何接口返回 401 都意味着会话已失效，统一退回登录页。
    setUnauthorizedHandler(() => setMe(null));
    check();
  }, [check]);

  const logout = async () => {
    try {
      await api.post("/auth/logout");
    } finally {
      queryClient.clear();
      setMe(null);
    }
  };

  if (checking) return <Loading label="检查登录状态" />;
  if (!me) return <Login onSuccess={check} />;

  return (
    <BrowserRouter>
      <Shell username={me.username} role={me.role} onLogout={logout}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/certificates" element={<Certificates />} />
            <Route path="/certificates/:id" element={<CertificateDetail />} />
            <Route path="/credentials" element={<Credentials />} />
            <Route path="/servers" element={<Servers />} />
            <Route path="/targets" element={<Targets />} />
            <Route path="/health" element={<Health />} />
            <Route path="/notifications" element={<Notifications />} />
            <Route path="/jobs" element={<Jobs />} />
            <Route path="/jobs/:id" element={<JobDetail />} />
            <Route path="/settings" element={<Settings />} />
      </Routes>
    </Shell>
  </BrowserRouter>
  );
}
