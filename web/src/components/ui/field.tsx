import { cn } from "@/lib/utils";

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-sm font-medium">{label}</span>
      {children}
      {hint && <span className="text-muted-foreground text-xs">{hint}</span>}
    </label>
  );
}

const control =
  "bg-card focus-visible:ring-ring h-9 w-full rounded-md border px-3 text-sm " +
  "focus-visible:ring-2 focus-visible:outline-none disabled:opacity-50";

export function Input({ className, ...props }: React.ComponentProps<"input">) {
  return <input className={cn(control, className)} {...props} />;
}

export function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return <textarea className={cn(control, "h-auto py-2 font-mono", className)} {...props} />;
}

export function Select({ className, ...props }: React.ComponentProps<"select">) {
  return <select className={cn(control, className)} {...props} />;
}

export function Checkbox({ className, ...props }: React.ComponentProps<"input">) {
  return <input type="checkbox" className={cn("size-4 rounded border", className)} {...props} />;
}
