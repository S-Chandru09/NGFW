import { cn } from "@/utils";

interface RiskScoreGaugeProps {
  trustScore: number;
  minRequiredScore: number;
  trustLevel: string;
  label?: string;
}

function getRiskColor(riskScore: number) {
  if (riskScore >= 70) {
    return { stroke: "#ef4444", text: "text-red-300", bg: "from-red-500/20 to-red-500/5" };
  }

  if (riskScore >= 50) {
    return { stroke: "#f97316", text: "text-orange-300", bg: "from-orange-500/20 to-orange-500/5" };
  }

  if (riskScore >= 30) {
    return { stroke: "#f59e0b", text: "text-amber-300", bg: "from-amber-500/20 to-amber-500/5" };
  }

  return { stroke: "#22c55e", text: "text-emerald-300", bg: "from-emerald-500/20 to-emerald-500/5" };
}

export default function RiskScoreGauge({
  trustScore,
  minRequiredScore,
  trustLevel,
  label = "Composite Risk Score",
}: RiskScoreGaugeProps) {
  const riskScore = Math.max(0, Math.min(100, Math.round(100 - trustScore)));
  const colors = getRiskColor(riskScore);
  const radius = 88;
  const circumference = 2 * Math.PI * radius;
  const progress = (riskScore / 100) * circumference;

  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center rounded-2xl border border-slate-800 bg-gradient-to-b p-6",
        colors.bg,
      )}
    >
      <p className="text-sm font-medium text-slate-400">{label}</p>

      <div className="relative mt-4 h-52 w-52">
        <svg className="h-full w-full -rotate-90" viewBox="0 0 200 200">
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="none"
            stroke="#1e293b"
            strokeWidth="14"
          />
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="none"
            stroke={colors.stroke}
            strokeWidth="14"
            strokeLinecap="round"
            strokeDasharray={`${progress} ${circumference}`}
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <p className={cn("text-4xl font-bold", colors.text)}>{riskScore}</p>
          <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">risk / 100</p>
        </div>
      </div>

      <div className="mt-4 grid w-full grid-cols-2 gap-3 text-center">
        <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
          <p className="text-xs text-slate-500">Trust Score</p>
          <p className="mt-1 text-lg font-semibold text-white">{trustScore.toFixed(1)}</p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
          <p className="text-xs text-slate-500">Min Required</p>
          <p className="mt-1 text-lg font-semibold text-white">{minRequiredScore.toFixed(1)}</p>
        </div>
      </div>

      <p className="mt-4 rounded-full border border-slate-700 px-3 py-1 text-xs uppercase tracking-wide text-slate-300">
        Trust Level: {trustLevel}
      </p>
    </div>
  );
}
