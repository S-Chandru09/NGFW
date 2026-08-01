import type { ReactNode } from "react";
import { cn, formatCompactNumber } from "@/utils";

interface StatCardProps {
  label: string;
  value: string | number;
  unit?: string;
  change?: number | null;
  trend?: string | null;
  icon?: ReactNode;
  accent?: "blue" | "green" | "amber" | "red" | "slate";
}

const accentStyles = {
  blue: "from-primary-500/20 to-primary-500/5 text-primary-300",
  green: "from-emerald-500/20 to-emerald-500/5 text-emerald-300",
  amber: "from-amber-500/20 to-amber-500/5 text-amber-300",
  red: "from-red-500/20 to-red-500/5 text-red-300",
  slate: "from-slate-500/20 to-slate-500/5 text-slate-300",
};

export default function StatCard({
  label,
  value,
  unit,
  change,
  trend,
  icon,
  accent = "blue",
}: StatCardProps) {
  const formattedValue =
    typeof value === "number" ? formatCompactNumber(value) : value;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm text-slate-500">{label}</p>
          <div className="mt-2 flex items-end gap-2">
            <p className="text-2xl font-semibold text-white">{formattedValue}</p>
            {unit ? <span className="pb-1 text-xs text-slate-500">{unit}</span> : null}
          </div>
        </div>

        {icon ? (
          <div
            className={cn(
              "flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br",
              accentStyles[accent],
            )}
          >
            {icon}
          </div>
        ) : null}
      </div>

      {change !== undefined && change !== null ? (
        <p
          className={cn(
            "mt-3 text-xs font-medium",
            trend === "up" ? "text-emerald-400" : "text-red-400",
          )}
        >
          {change > 0 ? "+" : ""}
          {change.toFixed(1)}% vs previous period
        </p>
      ) : null}
    </div>
  );
}
