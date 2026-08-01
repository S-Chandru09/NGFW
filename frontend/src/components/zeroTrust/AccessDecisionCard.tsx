import StatusBadge from "@/components/admin/StatusBadge";
import type { TrustScore, TrustScoreBreakdown } from "@/types/trustScore";
import { cn } from "@/utils";

interface AccessDecisionCardProps {
  trustScore: TrustScore | null;
  breakdown?: TrustScoreBreakdown | null;
  zeroTrustEnabled: boolean;
  minRequiredScore: number;
}

export default function AccessDecisionCard({
  trustScore,
  breakdown,
  zeroTrustEnabled,
  minRequiredScore,
}: AccessDecisionCardProps) {
  const isAllowed = trustScore?.is_access_allowed ?? false;
  const compositeScore = trustScore?.composite_score ?? 0;
  const activeBreakdown = breakdown ?? trustScore?.breakdown ?? null;

  return (
    <div
      className={cn(
        "rounded-2xl border p-6",
        isAllowed
          ? "border-emerald-500/30 bg-emerald-500/10"
          : "border-red-500/30 bg-red-500/10",
      )}
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400">Access Decision</p>
          <h3
            className={cn(
              "mt-2 text-3xl font-bold tracking-tight",
              isAllowed ? "text-emerald-300" : "text-red-300",
            )}
          >
            {isAllowed ? "ALLOW" : "DENY"}
          </h3>
          <p className="mt-2 text-sm text-slate-300">
            {isAllowed
              ? "Entity meets the minimum trust threshold for network access."
              : "Entity does not meet the minimum trust threshold. Access is restricted."}
          </p>
        </div>

        <div
          className={cn(
            "flex h-16 w-16 items-center justify-center rounded-2xl ring-1",
            isAllowed
              ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30"
              : "bg-red-500/15 text-red-300 ring-red-500/30",
          )}
        >
          {isAllowed ? (
            <svg className="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          ) : (
            <svg className="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          )}
        </div>
      </div>

      <div className="mt-6 grid gap-3 sm:grid-cols-3">
        <div className="rounded-xl border border-slate-800/80 bg-slate-950/40 p-4">
          <p className="text-xs text-slate-500">Composite Score</p>
          <p className="mt-1 text-xl font-semibold text-white">{compositeScore.toFixed(1)}</p>
        </div>
        <div className="rounded-xl border border-slate-800/80 bg-slate-950/40 p-4">
          <p className="text-xs text-slate-500">Required Threshold</p>
          <p className="mt-1 text-xl font-semibold text-white">{minRequiredScore.toFixed(1)}</p>
        </div>
        <div className="rounded-xl border border-slate-800/80 bg-slate-950/40 p-4">
          <p className="text-xs text-slate-500">Zero Trust Policy</p>
          <div className="mt-2">
            <StatusBadge
              label={zeroTrustEnabled ? "Enabled" : "Disabled"}
              variant={zeroTrustEnabled ? "success" : "muted"}
            />
          </div>
        </div>
      </div>

      {activeBreakdown ? (
        <div className="mt-6 space-y-3">
          <p className="text-sm font-medium text-slate-300">Decision Factors</p>
          <div className="grid gap-2 sm:grid-cols-3">
            {[
              { label: "Device", score: activeBreakdown.device_score },
              { label: "User", score: activeBreakdown.user_score },
              { label: "Behaviour", score: activeBreakdown.behaviour_score },
            ].map((item) => (
              <div
                key={item.label}
                className="rounded-lg border border-slate-800 bg-slate-950/30 px-3 py-2 text-sm"
              >
                <span className="text-slate-500">{item.label}</span>
                <span
                  className={cn(
                    "ml-2 font-semibold",
                    item.score >= minRequiredScore ? "text-emerald-300" : "text-amber-300",
                  )}
                >
                  {item.score.toFixed(1)}
                </span>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {trustScore?.username ? (
        <p className="mt-4 text-xs text-slate-500">
          Evaluated for <span className="text-slate-300">{trustScore.username}</span>
          {trustScore.device_name ? (
            <>
              {" "}
              on <span className="text-slate-300">{trustScore.device_name}</span>
            </>
          ) : null}
        </p>
      ) : null}
    </div>
  );
}
