import { AlertCircle, Loader2 } from "lucide-react";

export function Loading({ label = "加载中" }: { label?: string }) {
  return (
    <div className="text-muted-foreground flex items-center justify-center gap-2 py-12 text-sm">
      <Loader2 className="size-4 animate-spin" />
      {label}
    </div>
  );
}

/** 错误提示要说清楚发生了什么，并给出下一步动作。 */
export function ErrorNote({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div className="bg-danger-soft text-danger flex items-start gap-2 rounded-md border border-danger/30 p-3 text-sm">
      <AlertCircle className="mt-0.5 size-4 shrink-0" />
      <div className="flex flex-col items-start gap-1.5">
        <span>{msg}</span>
        {onRetry && (
          <button onClick={onRetry} className="underline underline-offset-2">
            重试
          </button>
        )}
      </div>
    </div>
  );
}

/** 空状态要解释这里将来会有什么，而不是只写「暂无数据」。 */
export function Empty({ title, hint, action }: { title: string; hint?: string; action?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 py-14 text-center">
      <p className="text-sm font-medium">{title}</p>
      {hint && <p className="text-muted-foreground max-w-sm text-xs">{hint}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}
