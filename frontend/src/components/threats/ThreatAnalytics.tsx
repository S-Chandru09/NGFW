import { useEffect } from "react";
import AttackSeverityPieChart from "@/components/threats/AttackSeverityPieChart";
import AttackTrendLineChart from "@/components/threats/AttackTrendLineChart";
import AttackTypesBarChart from "@/components/threats/AttackTypesBarChart";
import AttackVolumeBarChart from "@/components/threats/AttackVolumeBarChart";
import RecentThreatAlerts from "@/components/dashboard/RecentThreatAlerts";
import StatCard from "@/components/dashboard/StatCard";
import ThreatLevelCard from "@/components/dashboard/ThreatLevelCard";
import { useThreatAnalytics } from "@/hooks/useThreatAnalytics";
import { useThreatAlertSocket } from "@/providers/ThreatAlertSocketProvider";
import { cn, formatDateTime } from "@/utils";

interface ThreatAnalyticsProps {
  periodHours?: number;
  topLimit?: number;
  refreshIntervalMs?: number;
}

export default function ThreatAnalytics({
  periodHours = 24,
  topLimit = 10,
  refreshIntervalMs = 60000,
}: ThreatAnalyticsProps) {
  const { data, isLoading, isRefreshing, error, lastUpdated, refresh } = useThreatAnalytics({
    periodHours,
    topLimit,
    refreshIntervalMs,
  });
  const { subscribeToAlerts } = useThreatAlertSocket();

  useEffect(() => {
    return subscribeToAlerts(() => {
      refresh();
    });
  }, [subscribeToAlerts, refresh]);

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
        <h3 className="text-lg font-semibold text-red-300">Unable to load threat analytics</h3>
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

  const {
    attack_count: attacks,
    threat_level: threatLevel,
    top_attack_types: topAttackTypes,
    traffic_summary: traffic,
    recent_threat_alerts: recentAlerts,
  } = data.data;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-xl font-semibold text-white">Threat Analytics</h2>
          <p className="mt-1 text-sm text-slate-400">
            Attack trends, severity distribution, and top threat categories
          </p>
        </div>

        <div className="flex items-center gap-3">
          {lastUpdated ? (
            <p className="text-xs text-slate-500">
              Updated {formatDateTime(lastUpdated)}
            </p>
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
        </div>
      </div>

      {error ? (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
          {error}
        </div>
      ) : null}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total Attacks"
          value={attacks.total_attacks}
          accent="red"
          icon={
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
            </svg>
          }
        />
        <StatCard label="Blocked Attacks" value={attacks.blocked_attacks} accent="amber" />
        <StatCard label="Active Alerts" value={attacks.active_alerts} accent="red" />
        <StatCard label="Resolved Alerts" value={attacks.resolved_alerts} accent="green" />
      </div>

      <ThreatLevelCard threatLevel={threatLevel} />

      <RecentThreatAlerts
        alerts={recentAlerts ?? []}
        title="Latest Threat Alerts"
        description="Individual alerts created from PCAP analysis and network flow ingest"
      />

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-white">Attack Trends</h3>
          <p className="text-sm text-slate-500">
            Hourly threat detections over the last {traffic.period_hours} hours
          </p>
        </div>
        <AttackTrendLineChart data={traffic.hourly_trend} />
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-white">Severity Distribution</h3>
            <p className="text-sm text-slate-500">Attacks grouped by severity level</p>
          </div>
          <AttackSeverityPieChart attacks={attacks} />
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-white">Attack Volume</h3>
            <p className="text-sm text-slate-500">Detected attacks by time period</p>
          </div>
          <AttackVolumeBarChart attacks={attacks} />
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-white">Top Attack Types</h3>
          <p className="text-sm text-slate-500">
            Most frequent threat categories in the selected period
          </p>
        </div>
        <AttackTypesBarChart data={topAttackTypes} />
      </div>

      {topAttackTypes.length > 0 ? (
        <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60">
          <div className="border-b border-slate-800 px-5 py-4">
            <h3 className="text-lg font-semibold text-white">Recent Attack Details</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-800">
              <thead className="bg-slate-950/60">
                <tr>
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                    Threat Type
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                    Count
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                    Share
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                    Severity
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                    Last Detected
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {topAttackTypes.map((attack) => (
                  <tr key={attack.threat_type} className="hover:bg-slate-900/50">
                    <td className="px-5 py-4 text-sm font-medium text-white">
                      {attack.threat_type.replace(/_/g, " ")}
                    </td>
                    <td className="px-5 py-4 text-sm text-slate-300">{attack.count}</td>
                    <td className="px-5 py-4 text-sm text-slate-300">{attack.percentage}%</td>
                    <td className="px-5 py-4">
                      <span
                        className={cn(
                          "rounded-full px-2.5 py-1 text-xs font-medium capitalize",
                          attack.severity === "critical" && "bg-red-500/10 text-red-300",
                          attack.severity === "high" && "bg-orange-500/10 text-orange-300",
                          attack.severity === "medium" && "bg-amber-500/10 text-amber-300",
                          attack.severity === "low" && "bg-emerald-500/10 text-emerald-300",
                        )}
                      >
                        {attack.severity}
                      </span>
                    </td>
                    <td className="px-5 py-4 text-sm text-slate-400">
                      {attack.last_detected_at
                        ? formatDateTime(attack.last_detected_at)
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </div>
  );
}
