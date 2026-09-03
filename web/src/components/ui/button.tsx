import { cn } from "@/lib/utils";

type Variant = "default" | "outline" | "ghost" | "danger";
type Size = "sm" | "md";

const variants: Record<Variant, string> = {
  default: "bg-primary text-primary-foreground hover:opacity-90",
  outline: "border bg-card hover:bg-accent",
  ghost: "hover:bg-accent",
  danger: "border border-danger/40 text-danger hover:bg-danger-soft",
};

const sizes: Record<Size, string> = {
  sm: "h-8 px-3 text-xs",
  md: "h-9 px-4 text-sm",
};

export function Button({
  className,
  variant = "default",
  size = "md",
  ...props
}: React.ComponentProps<"button"> & { variant?: Variant; size?: Size }) {
  return (
    <button
      className={cn(
        "focus-visible:ring-ring inline-flex items-center justify-center gap-1.5 rounded-md font-medium",
        "transition-colors focus-visible:ring-2 focus-visible:outline-none",
        "disabled:pointer-events-none disabled:opacity-50",
        variants[variant],
        sizes[size],
        className,
      )}
      {...props}
    />
  );
}
