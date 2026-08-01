import AccessDecisionCard from "@/components/zeroTrust/AccessDecisionCard";
import AccessDecisionPieChart from "@/components/zeroTrust/AccessDecisionPieChart";
import RiskScoreGauge from "@/components/zeroTrust/RiskScoreGauge";
import TrustComponentBarChart from "@/components/zeroTrust/TrustComponentBarChart";
import TrustLevelPieChart from "@/components/zeroTrust/TrustLevelPieChart";
import TrustScoreTable from "@/components/zeroTrust/TrustScoreTable";
import TrustScoreTrendChart from "@/components/zeroTrust/TrustScoreTrendChart";
import StatCard from "@/components/dashboard/StatCard";
import { useAuth } from "@/hooks/useAuth";
import { useZeroTrustDashboard } from "@/hooks/useZeroTrustDashboard";
import { cn, formatDateTime } from "@/utils";

export default function ZeroTrustDashboard() {
  const { user } = useAuth();
  const { data, isLoading, isRefreshing, error, lastUpdated, refresh } = useZeroTrustDashboard({
    userId: user?.id,
    refreshIntervalMs: 60000,
  });

  if (isLoading && !data) {
    return (
      <div className="flex min-h-[320px] items-center justify-center rounded-2xl border border-slate-800 bg-slate-900/40">
        <div className="h-10 w-10 animate-spin rounded-full border-2 border-primary-500 border-t-transparent" />
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-6">
        <h3 className="text-lg font-semibold text-red-300">Unable to load Zero Trust dashboard</h3>
        <p className="mt-2 text-sm text-red-200/80">{error}</p>
        <button
          type="button"
          onClick={refresh}
          className="mt-4 rounded-lg bg-red-500/20 px-4 py-2 text-sm font-medium text-red-200 transition hover:bg-red-500/30"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!data) {
    return null;
  }

  const { stats, recentScores, currentUserScore } = data;
  const featuredScore = currentUserScore ?? recentScores[0] ?? null;
  const featuredTrustScore = featuredScore?.composite_score ?? stats.average_composite_score;
  const featuredTrustLevel = featuredScore?.trust_level ?? "medium";

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-xl font-semibold text-white">Zero Trust Dashboard</h2>
          <p className="mt-1 text-sm text-slate-400">
            Continuous trust evaluation with risk scoring and access decisions
          </p>
        </div>

        <div className="flex items-center gap-3">
          {lastUpdated ? (
            <p className="text-xs text-slate-500">Updated {formatDateTime(lastUpdated)}</p>
          ) : null}
          <button
            type="button"
            onClick={refresh}
            disabled={isRefreshing}
            className={cn(
              "rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 transition hover:bg-slate-800",
              "disabled:cursor-not-allowed disabled:opacity-60",
            )}
          >
            {isRefreshing ? "Refreshing..." : "Refresh"}
          </button>
          <span
            className={cn(
              "inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium",
              stats.zero_trust_enabled
                ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-300"
                : "border-amber-500/20 bg-amber-500/10 text-amber-300",
            )}
          >
            <span
              className={cn(
                "h-2 w-2 rounded-full",
                stats.zero_trust_enabled ? "bg-emerald-400" : "bg-amber-400",
              )}
            />
            Zero Trust {stats.zero_trust_enabled ? "Active" : "Inactive"}
          </span>
        </div>
      </div>

      {error ? (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
          {error}
        </div>
      ) : null}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Evaluated Entities"
          value={stats.total_scores}
          accent="blue"
        />
        <StatCard
          label="Average Trust Score"
          value={stats.average_composite_score.toFixed(1)}
          accent="green"
        />
        <StatCard
          label="Access Allowed"
          value={stats.access_allowed_count}
          accent="green"
        />
        <StatCard
          label="Access Denied"
          value={stats.access_denied_count}
          accent="red"
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <RiskScoreGauge
          trustScore={featuredTrustScore}
          minRequiredScore={stats.min_required_score}
          trustLevel={featuredTrustLevel}
          label={currentUserScore ? "Your Risk Score" : "Platform Risk Score"}
        />

        <div className="xl:col-span-2">
          <AccessDecisionCard
            trustScore={featuredScore}
            zeroTrustEnabled={stats.zero_trust_enabled}
            minRequiredScore={stats.min_required_score}
          />
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2 xl:grid-cols-3">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
          <h3 className="text-sm font-semibold text-white">Trust Component Scores</h3>
          <p className="mt-1 text-xs text-slate-500">Device, user, and behaviour averages</p>
          <div className="mt-4">
            <TrustComponentBarChart stats={stats} />
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
          <h3 className="text-sm font-semibold text-white">Trust Level Distribution</h3>
          <p className="mt-1 text-xs text-slate-500">Entities grouped by trust level</p>
          <div className="mt-4">
            <TrustLevelPieChart distribution={stats.trust_level_distribution} />
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
          <h3 className="text-sm font-semibold text-white">Access Decisions</h3>
          <p className="mt-1 text-xs text-slate-500">Allow vs deny outcomes</p>
          <div className="mt-4">
            <AccessDecisionPieChart
              allowed={stats.access_allowed_count}
              denied={stats.access_denied_count}
            />
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
        <h3 className="text-sm font-semibold text-white">Trust & Risk Trend</h3>
        <p className="mt-1 text-xs text-slate-500">Recent score changes across all components</p>
        <div className="mt-4">
          <TrustScoreTrendChart scores={recentScores} />
        </div>
      </div>

      <div>
        <h3 className="mb-4 text-sm font-semibold text-white">Recent Trust Evaluations</h3>
        <TrustScoreTable scores={recentScores} />
      </div>
    </div>
  );
}
