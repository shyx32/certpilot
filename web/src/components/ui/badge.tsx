import { cn } from "@/lib/utils";
import type { CertState } from "@/lib/utils";

const styles: Record<CertState, string> = {
  ok: "bg-ok-soft text-ok border-ok/30",
  warn: "bg-warn-soft text-warn border-warn/30",
  danger: "bg-danger-soft text-danger border-danger/30",
  busy: "bg-busy-soft text-busy border-busy/30",
};

/**
 * 状态同时用颜色和形状编码——色觉障碍用户看不出红绿差别，
 * 所以圆点与文字标签都不能省。
 */
export function StatusBadge({ state, children }: { state: CertState; children: React.ReactNode }) {
  return (
    <span
      className={cn(
        "inline-flex w-fit self-start items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        styles[state],
      )}
    >
      <span className="size-1.5 rounded-full bg-current" aria-hidden />
      {children}
    </span>
  );
}
