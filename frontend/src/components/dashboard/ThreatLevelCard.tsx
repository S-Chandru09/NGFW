import type { ThreatLevelBreakdown } from "@/types/dashboard";
import { cn } from "@/utils";

interface ThreatLevelCardProps {
  threatLevel: ThreatLevelBreakdown;
}

const levelStyles: Record<string, string> = {
  safe: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  low: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  medium: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  critical: "text-red-400 bg-red-500/10 border-red-500/20",
};

export default function ThreatLevelCard({ threatLevel }: ThreatLevelCardProps) {
  const level = threatLevel.overall_level.toLowerCase();
  const style = levelStyles[level] || levelStyles.medium;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm text-slate-500">Current Threat Level</p>
          <div className="mt-3 flex items-end gap-3">
            <span className={cn("rounded-full border px-3 py-1 text-sm font-semibold capitalize", style)}>
              {threatLevel.overall_level}
            </span>
            <span className="text-3xl font-bold text-white">
              {threatLevel.overall_score.toFixed(0)}
            </span>
            <span className="pb-1 text-sm text-slate-500">/ 100</span>
          </div>
        </div>

        <div className="text-right">
          <p className="text-xs uppercase tracking-wide text-slate-500">Risk Trend</p>
          <p className="mt-1 text-sm font-medium capitalize text-slate-200">
            {threatLevel.risk_trend}
          </p>
        </div>
      </div>

      <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          { label: "Critical", value: threatLevel.critical_count, color: "text-red-400" },
          { label: "High", value: threatLevel.high_count, color: "text-orange-400" },
          { label: "Medium", value: threatLevel.medium_count, color: "text-amber-400" },
          { label: "Low", value: threatLevel.low_count, color: "text-emerald-400" },
        ].map((item) => (
          <div key={item.label} className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
            <p className="text-xs text-slate-500">{item.label}</p>
            <p className={cn("mt-1 text-lg font-semibold", item.color)}>{item.value}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
