import { cn } from "@/utils";

type BadgeVariant = "default" | "success" | "warning" | "danger" | "info" | "muted";

interface StatusBadgeProps {
  label: string;
  variant?: BadgeVariant;
  className?: string;
}

const variantStyles: Record<BadgeVariant, string> = {
  default: "bg-slate-700/50 text-slate-200 ring-slate-600/50",
  success: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  warning: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  danger: "bg-red-500/15 text-red-300 ring-red-500/30",
  info: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
  muted: "bg-slate-800 text-slate-400 ring-slate-700",
};

export default function StatusBadge({ label, variant = "default", className }: StatusBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset",
        variantStyles[variant],
        className,
      )}
    >
      {label}
    </span>
  );
}

export function roleBadgeVariant(role: string): BadgeVariant {
  switch (role) {
    case "admin":
      return "danger";
    case "analyst":
      return "info";
    default:
      return "muted";
  }
}

export function severityBadgeVariant(severity: string): BadgeVariant {
  switch (severity) {
    case "critical":
      return "danger";
    case "error":
      return "danger";
    case "warning":
      return "warning";
    case "info":
      return "info";
    default:
      return "muted";
  }
}

export function threatLevelBadgeVariant(level: string): BadgeVariant {
  switch (level) {
    case "critical":
    case "high":
      return "danger";
    case "medium":
      return "warning";
    case "low":
      return "info";
    default:
      return "success";
  }
}

export function actionBadgeVariant(action: string): BadgeVariant {
  switch (action) {
    case "allow":
    case "whitelist":
      return "success";
    case "block":
    case "blacklist":
    case "temporary_block":
      return "danger";
    default:
      return "default";
  }
}
