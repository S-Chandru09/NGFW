import { useEffect, useState } from "react";
import ProtocolDistributionChart from "@/components/dashboard/ProtocolDistributionChart";
import RecentThreatAlerts from "@/components/dashboard/RecentThreatAlerts";
import StatCard from "@/components/dashboard/StatCard";
import ThreatLevelCard from "@/components/dashboard/ThreatLevelCard";
import TrafficTrendChart from "@/components/dashboard/TrafficTrendChart";
import { useLiveTraffic } from "@/hooks/useLiveTraffic";
import { useThreatAlertSocket } from "@/providers/ThreatAlertSocketProvider";
import { getApiErrorMessage } from "@/services/apiClient";
import { runLiveCapture } from "@/services/liveCaptureService";
import { cn, formatBytes, formatDateTime } from "@/utils";

interface LiveTrafficProps {
  periodHours?: number;
  refreshIntervalMs?: number;
}

export default function LiveTraffic({
  periodHours = 24,
  refreshIntervalMs = 30000,
}: LiveTrafficProps) {
  const { data, isLoading, isRefreshing, error, lastUpdated, refresh } = useLiveTraffic({
    periodHours,
    refreshIntervalMs,
  });
  const { subscribeToAlerts, status: alertSocketStatus } = useThreatAlertSocket();
  const [isCapturing, setIsCapturing] = useState(false);
  const [captureMessage, setCaptureMessage] = useState<string | null>(null);
  const [captureError, setCaptureError] = useState<string | null>(null);

  useEffect(() => {
    return subscribeToAlerts(() => {
      refresh();
    });
  }, [subscribeToAlerts, refresh]);

  const handleLiveCapture = async () => {
    setIsCapturing(true);
    setCaptureMessage(null);
    setCaptureError(null);

    try {
      const response = await runLiveCapture({
        packet_count: 50,
        timeout_seconds: 30,
        send_to_backend: true,
      });
      setCaptureMessage(
        `Live capture complete: ${response.packets_processed} packets, ${response.threats_detected} threats detected.`,
      );
      await refresh();
    } catch (captureFailure) {
      setCaptureError(getApiErrorMessage(captureFailure, "Live capture failed"));
    } finally {
      setIsCapturing(false);
    }
  };

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
        <h3 className="text-lg font-semibold text-red-300">Unable to load live traffic</h3>
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

  const { traffic_summary: traffic, attack_count: attacks, threat_level: threatLevel, kpis, recent_threat_alerts: recentAlerts } =
    data.data;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-xl font-semibold text-white">Live Traffic</h2>
          <p className="mt-1 text-sm text-slate-400">
            Real-time network flow monitoring for the last {traffic.period_hours} hours
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
            onClick={handleLiveCapture}
            disabled={isCapturing}
            className={cn(
              "rounded-lg border border-primary-500/40 bg-primary-500/10 px-3 py-2 text-sm text-primary-200 transition hover:bg-primary-500/20",
              "disabled:cursor-not-allowed disabled:opacity-60",
            )}
          >
            {isCapturing ? "Capturing..." : "Run Live Capture"}
          </button>
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
          <span className="inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300">
            <span
              className={cn(
                "h-2 w-2 rounded-full",
                alertSocketStatus === "connected" ? "animate-pulse bg-emerald-400" : "bg-amber-400",
              )}
            />
            {alertSocketStatus === "connected" ? "Alerts Live" : "Alerts Polling"}
          </span>
        </div>
      </div>

      {error ? (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
          {error}
        </div>
      ) : null}

      {captureMessage ? (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
          {captureMessage}
        </div>
      ) : null}

      {captureError ? (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          {captureError}
        </div>
      ) : null}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total Flows"
          value={traffic.total_flows}
          accent="blue"
          icon={
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
            </svg>
          }
        />
        <StatCard
          label="Threat Flows"
          value={traffic.threat_flows}
          accent="red"
          icon={
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
            </svg>
          }
        />
        <StatCard
          label="Blocked Flows"
          value={traffic.blocked_flows}
          accent="amber"
          icon={
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
            </svg>
          }
        />
        <StatCard
          label="Total Bandwidth"
          value={formatBytes(traffic.total_bytes)}
          accent="green"
          icon={
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          }
        />
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total Packets" value={traffic.total_packets} accent="slate" />
        <StatCard label="Allowed Flows" value={traffic.allowed_flows} accent="green" />
        <StatCard label="Active Alerts" value={attacks.active_alerts} accent="red" />
        <StatCard label="Attacks Today" value={attacks.attacks_today} accent="amber" />
      </div>

      {kpis.length > 0 ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {kpis.slice(0, 4).map((kpi) => (
            <StatCard
              key={kpi.label}
              label={kpi.label}
              value={kpi.value}
              unit={kpi.unit || undefined}
              change={kpi.change_percentage}
              trend={kpi.trend}
              accent="blue"
            />
          ))}
        </div>
      ) : null}

      <ThreatLevelCard threatLevel={threatLevel} />

      <RecentThreatAlerts alerts={recentAlerts ?? []} />

      <div className="grid gap-6 xl:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 xl:col-span-2">
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-white">Traffic Trend</h3>
            <p className="text-sm text-slate-500">Hourly flows and detected threats</p>
          </div>
          <TrafficTrendChart data={traffic.hourly_trend} />
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <h3 className="text-lg font-semibold text-white">Traffic Breakdown</h3>
          <div className="mt-4 space-y-4">
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-4">
              <p className="text-xs text-slate-500">Inbound</p>
              <p className="mt-1 text-lg font-semibold text-white">
                {formatBytes(traffic.inbound_bytes)}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-4">
              <p className="text-xs text-slate-500">Outbound</p>
              <p className="mt-1 text-lg font-semibold text-white">
                {formatBytes(traffic.outbound_bytes)}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-4">
              <p className="text-xs text-slate-500">Unique Source IPs</p>
              <p className="mt-1 text-lg font-semibold text-white">
                {traffic.unique_source_ips}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-4">
              <p className="text-xs text-slate-500">Unique Destination IPs</p>
              <p className="mt-1 text-lg font-semibold text-white">
                {traffic.unique_destination_ips}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-white">Protocol Distribution</h3>
          <p className="text-sm text-slate-500">Flow volume by network protocol</p>
        </div>
        <ProtocolDistributionChart data={traffic.protocols} />
      </div>
    </div>
  );
}
