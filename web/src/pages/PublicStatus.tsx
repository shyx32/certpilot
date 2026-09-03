import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { ShieldCheck } from "lucide-react";

interface Row {
  domain: string;
  severity: string;
  days_left?: number;
  reachable: boolean;
}

interface Status {
  name: string;
  domains: Row[];
  ok: number;
  warn: number;
  danger: number;
  generated_at: string;
}

const styles: Record<string, string> = {
  danger: "bg-danger-soft text-danger border-danger/30",
  warn: "bg-warn-soft text-warn border-warn/30",
  "": "bg-ok-soft text-ok border-ok/30",
};

const labels: Record<string, string> = { danger: "异常", warn: "注意", "": "正常" };

/**
 * 只读状态页。不需要登录，因此刻意不复用后台的 Shell——
 * 侧栏、用户信息、任何操作入口都不该出现在这里。
 */
export function PublicStatus() {
  const { token } = useParams();
  const [data, setData] = useState<Status>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    fetch(`/api/v1/public/status/${token}`)
      .then(async (r) => {
        if (!r.ok) throw new Error((await r.json()).error ?? "链接无效");
        return r.json();
      })
      .then(setData)
      .catch((e) => setError(e.message));
  }, [token]);

  if (error) {
    return (
      <div className="bg-background flex min-h-screen items-center justify-center p-6">
        <p className="text-muted-foreground text-sm">{error}</p>
      </div>
    );
  }
  if (!data) {
    return (
      <div className="bg-background flex min-h-screen items-center justify-center p-6">
        <p className="text-muted-foreground text-sm">加载中…</p>
      </div>
    );
  }

  return (
    <div className="bg-background min-h-screen p-6">
      <div className="mx-auto max-w-3xl space-y-5">
        <header className="flex items-center gap-2.5">
          <div className="bg-primary text-primary-foreground grid size-8 place-items-center rounded-md">
            <ShieldCheck className="size-4" />
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-tight">{data.name}</h1>
            <p className="text-muted-foreground text-xs">
              更新于 {new Date(data.generated_at).toLocaleString("zh-CN", { hour12: false })}
            </p>
          </div>
        </header>

        <div className="grid gap-3 sm:grid-cols-3">
          <Tile label="正常" value={data.ok} />
          <Tile label="注意" value={data.warn} tone={data.warn > 0 ? "warn" : undefined} />
          <Tile label="异常" value={data.danger} tone={data.danger > 0 ? "danger" : undefined} />
        </div>

        <div className="bg-card overflow-hidden rounded-lg border">
          {data.domains.length === 0 ? (
            <p className="text-muted-foreground p-6 text-center text-sm">还没有巡检数据。</p>
          ) : (
            <ul className="divide-y">
              {data.domains.map((d) => (
                <li key={d.domain} className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5">
                  <span className="font-medium">{d.domain}</span>
                  <div className="flex items-center gap-3">
                    <span className="text-muted-foreground tabular text-xs">
                      {d.days_left == null ? (d.reachable ? "—" : "无法连接") : `剩余 ${d.days_left} 天`}
                    </span>
                    <span
                      className={
                        "rounded-full border px-2 py-0.5 text-xs font-medium " +
                        (styles[d.severity] ?? styles.warn)
                      }
                    >
                      {labels[d.severity] ?? "注意"}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <p className="text-muted-foreground text-center text-xs">由 CertPilot 自动巡检生成</p>
      </div>
    </div>
  );
}

function Tile({ label, value, tone }: { label: string; value: number; tone?: "warn" | "danger" }) {
  return (
    <div className="bg-card rounded-lg border px-4 py-3.5">
      <div className="text-muted-foreground text-xs font-medium">{label}</div>
      <div
        className={
          "tabular mt-1 text-2xl leading-none font-semibold " +
          (tone === "danger" ? "text-danger" : tone === "warn" ? "text-warn" : "")
        }
      >
        {value}
      </div>
    </div>
  );
}
