/** 页面标题区：标题 + 一句说明 + 右侧操作，统一各页的起手式。 */
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0 space-y-0.5">
        <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
        {description && <p className="text-muted-foreground text-sm">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

/** 统计卡片。数字优先，说明其次。 */
export function Stat({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: number | string;
  hint?: string;
  tone?: "warn" | "danger";
}) {
  return (
    <div className="bg-card rounded-lg border px-4 py-3.5 shadow-xs">
      <div className="text-muted-foreground text-xs font-medium">{label}</div>
      <div
        className={
          "tabular mt-1 text-2xl leading-none font-semibold " +
          (tone === "danger" ? "text-danger" : tone === "warn" ? "text-warn" : "")
        }
      >
        {value}
      </div>
      {hint && <div className="text-muted-foreground mt-1.5 text-xs">{hint}</div>}
    </div>
  );
}
