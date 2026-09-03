import { NavLink, useLocation } from "react-router-dom";
import {
  LayoutDashboard, ShieldCheck, Server, KeyRound,
  ScrollText, Settings2, Moon, Sun, LogOut, ChevronRight,
} from "lucide-react";
import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";

/** 侧栏按用户心智分组，而不是按数据表分组。 */
const groups = [
  {
    label: "概览",
    items: [{ to: "/", icon: LayoutDashboard, label: "仪表盘", end: true }],
  },
  {
    label: "证书",
    items: [{ to: "/certificates", icon: ShieldCheck, label: "证书列表" }],
  },
  {
    label: "接入",
    items: [
      { to: "/targets", icon: Server, label: "部署目标" },
      // 凭据独立成项：它是全系统权限最敏感的地方，
      // 单独一栏比藏进设置二级菜单更容易被审视。
      { to: "/credentials", icon: KeyRound, label: "凭据" },
    ],
  },
  {
    label: "系统",
    items: [
      { to: "/jobs", icon: ScrollText, label: "任务与日志" },
      { to: "/settings", icon: Settings2, label: "CA 账号" },
    ],
  },
];

/** 路径 → 面包屑，让顶栏始终告诉用户「我在哪」。 */
const crumbs: Record<string, string> = {
  "/": "仪表盘",
  "/certificates": "证书列表",
  "/targets": "部署目标",
  "/credentials": "凭据",
  "/jobs": "任务与日志",
  "/settings": "CA 账号",
};

function useCrumb() {
  const { pathname } = useLocation();
  if (crumbs[pathname]) return [crumbs[pathname]];
  if (pathname.startsWith("/certificates/")) return ["证书列表", "详情"];
  if (pathname.startsWith("/jobs/")) return ["任务与日志", "执行详情"];
  return ["仪表盘"];
}

function useTheme() {
  const [dark, setDark] = useState(() => {
    const saved = localStorage.getItem("cp-theme");
    if (saved) return saved === "dark";
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  });
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    localStorage.setItem("cp-theme", dark ? "dark" : "light");
  }, [dark]);
  return { dark, toggle: () => setDark((d) => !d) };
}

const iconButton =
  "hover:bg-accent focus-visible:ring-ring grid size-8 place-items-center rounded-md " +
  "text-muted-foreground hover:text-foreground transition-colors " +
  "focus-visible:ring-2 focus-visible:outline-none";

export function Shell({
  children,
  username,
  role,
  onLogout,
}: {
  children: React.ReactNode;
  username: string;
  role: string;
  onLogout: () => void;
}) {
  const { dark, toggle } = useTheme();
  const crumb = useCrumb();

  return (
    <div className="bg-background flex min-h-screen">
      <aside className="bg-card hidden w-56 shrink-0 border-r md:flex md:flex-col">
        <div className="flex h-14 items-center gap-2.5 border-b px-4">
          <div className="bg-primary text-primary-foreground grid size-6 shrink-0 place-items-center rounded text-xs font-bold">
            C
          </div>
          <span className="text-sm font-semibold tracking-tight">CertPilot</span>
        </div>

        <nav className="flex-1 space-y-6 overflow-y-auto px-3 py-4">
          {groups.map((g) => (
            <div key={g.label} className="space-y-1">
              <div className="text-muted-foreground px-2 text-[11px] font-medium tracking-wide uppercase">
                {g.label}
              </div>
              <div className="space-y-0.5">
                {g.items.map((it) => (
                  <NavLink
                    key={it.to}
                    to={it.to}
                    end={"end" in it ? it.end : false}
                    className={({ isActive }) =>
                      cn(
                        "flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors",
                        isActive
                          ? "bg-accent text-accent-foreground font-medium"
                          : "text-muted-foreground hover:bg-accent/60 hover:text-accent-foreground",
                      )
                    }
                  >
                    <it.icon className="size-4 shrink-0" />
                    {it.label}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        <div className="text-muted-foreground border-t px-4 py-3 text-[11px]">
          证书私钥加密存放<br />主密钥不在数据库中
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="bg-background/80 sticky top-0 z-20 flex h-14 shrink-0 items-center justify-between gap-3 border-b px-6 backdrop-blur">
          <nav aria-label="面包屑" className="flex min-w-0 items-center gap-1.5 text-sm">
            {crumb.map((c, i) => (
              <span key={c} className="flex items-center gap-1.5">
                {i > 0 && <ChevronRight className="text-muted-foreground size-3.5" />}
                <span className={i === crumb.length - 1 ? "font-medium" : "text-muted-foreground"}>
                  {c}
                </span>
              </span>
            ))}
          </nav>

          <div className="flex shrink-0 items-center gap-2">
            <span className="text-muted-foreground hidden text-xs sm:inline">
              {username}
              <span className="bg-muted ml-1.5 rounded px-1.5 py-0.5">
                {role === "admin" ? "管理员" : role === "operator" ? "操作员" : "只读"}
              </span>
            </span>
            <button onClick={toggle} aria-label={dark ? "切换到亮色主题" : "切换到暗色主题"} className={iconButton}>
              {dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
            </button>
            <button onClick={onLogout} aria-label="退出登录" title="退出登录" className={iconButton}>
              <LogOut className="size-4" />
            </button>
          </div>
        </header>

        {/* 超宽屏上限制内容宽度，否则表格会被拉扯得难以扫读 */}
        <main className="min-w-0 flex-1">
          <div className="mx-auto max-w-[1400px] px-6 py-6">{children}</div>
        </main>
      </div>
    </div>
  );
}
