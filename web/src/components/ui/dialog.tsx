import { useEffect } from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

/** 轻量模态框。Esc 关闭、点击遮罩关闭、打开时锁定背景滚动。 */
export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  className,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: React.ReactNode;
  className?: string;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:p-8">
      <div
        className="fixed inset-0 bg-black/40"
        onClick={onClose}
        aria-hidden
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={cn(
          "bg-card relative z-10 my-auto w-full max-w-lg rounded-lg border p-5 shadow-lg",
          className,
        )}
      >
        <div className="mb-4 flex items-start justify-between gap-4">
          <div className="flex flex-col gap-1">
            <h2 className="text-base font-semibold">{title}</h2>
            {description && <p className="text-muted-foreground text-xs">{description}</p>}
          </div>
          <button
            onClick={onClose}
            aria-label="关闭"
            className="hover:bg-accent focus-visible:ring-ring -mt-1 grid size-7 shrink-0 place-items-center rounded-md focus-visible:ring-2 focus-visible:outline-none"
          >
            <X className="size-4" />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
