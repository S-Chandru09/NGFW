import NetworkGraphViewer from "@/components/network/NetworkGraphViewer";
import StatCard from "@/components/dashboard/StatCard";
import { useNetworkGraph } from "@/hooks/useNetworkGraph";
import { cn, formatDateTime } from "@/utils";

interface NetworkGraphProps {
  periodHours?: number;
  maxNodes?: number;
  refreshIntervalMs?: number;
}

export default function NetworkGraph({
  periodHours = 24,
  maxNodes = 40,
  refreshIntervalMs = 60000,
}: NetworkGraphProps) {
  const { data, isLoading, isRefreshing, error, refresh } = useNetworkGraph({
    periodHours,
    maxNodes,
    refreshIntervalMs,
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
        <h3 className="text-lg font-semibold text-red-300">Unable to load network graph</h3>
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

  const { metadata } = data.data;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-xl font-semibold text-white">Network Graph</h2>
          <p className="mt-1 text-sm text-slate-400">
            NetworkX graph visualization of IP communication flows
          </p>
        </div>

        <div className="flex items-center gap-3">
          <p className="text-xs text-slate-500">
            Layout: {metadata.layout_algorithm} • Updated {formatDateTime(metadata.generated_at)}
          </p>
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
        <StatCard label="Nodes" value={metadata.node_count} accent="blue" />
        <StatCard label="Edges" value={metadata.edge_count} accent="slate" />
        <StatCard
          label="Layout"
          value={metadata.layout_algorithm}
          accent="green"
        />
        <StatCard
          label="Period"
          value={`${metadata.period_hours}h`}
          accent="amber"
        />
      </div>

      <NetworkGraphViewer graph={data.data} />
    </div>
  );
}
