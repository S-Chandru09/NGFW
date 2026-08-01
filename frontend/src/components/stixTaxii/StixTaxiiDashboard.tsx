import { useCallback, useEffect, useState } from "react";
import DataTable, { type Column } from "@/components/admin/DataTable";
import StatCard from "@/components/dashboard/StatCard";
import StixObjectTypeChart from "@/components/stixTaxii/StixObjectTypeChart";
import StixObjectsTable from "@/components/stixTaxii/StixObjectsTable";
import TaxiiCollectionsTable from "@/components/stixTaxii/TaxiiCollectionsTable";
import { getApiErrorMessage } from "@/services/apiClient";
import {
  fetchStixObjects,
  fetchTaxiiStats,
  syncTaxiiSimulation,
} from "@/services/stixTaxiiService";
import type { PaginationMeta } from "@/types/admin";
import type { StixObject, StixObjectTypeFilter, TaxiiSimulationStats } from "@/types/stixTaxii";
import { cn, formatDateTime } from "@/utils";

const objectTypeFilters: Array<{ id: StixObjectTypeFilter; label: string }> = [
  { id: "all", label: "All Types" },
  { id: "indicator", label: "Indicators" },
  { id: "malware", label: "Malware" },
  { id: "threat-actor", label: "Threat Actors" },
  { id: "attack-pattern", label: "Attack Patterns" },
];

const endpointColumns: Column<{ label: string; path: string }>[] = [
  {
    key: "label",
    header: "Endpoint",
    render: (row) => <span className="text-slate-300">{row.label}</span>,
  },
  {
    key: "path",
    header: "Path",
    render: (row) => <span className="font-mono text-xs text-primary-300">{row.path}</span>,
  },
];

export default function StixTaxiiDashboard() {
  const [stats, setStats] = useState<TaxiiSimulationStats | null>(null);
  const [objects, setObjects] = useState<StixObject[]>([]);
  const [pagination, setPagination] = useState<PaginationMeta | null>(null);
  const [objectTypeFilter, setObjectTypeFilter] = useState<StixObjectTypeFilter>("all");
  const [page, setPage] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const [statsResponse, objectsResponse] = await Promise.all([
        fetchTaxiiStats(),
        fetchStixObjects({
          page,
          page_size: 10,
          object_type: objectTypeFilter === "all" ? undefined : objectTypeFilter,
        }),
      ]);

      setStats(statsResponse);
      setObjects(objectsResponse.items);
      setPagination(objectsResponse.pagination);
    } catch (loadError) {
      setError(getApiErrorMessage(loadError, "Failed to load STIX/TAXII simulation"));
    } finally {
      setIsLoading(false);
    }
  }, [objectTypeFilter, page]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleSync = async () => {
    setIsSyncing(true);
    setActionMessage(null);
    setError(null);

    try {
      const response = await syncTaxiiSimulation();
      setActionMessage(
        `Sync complete: ${response.objects_created} created, ${response.objects_updated} updated across ${response.collections_synced} collections.`,
      );
      setPage(1);
      await loadData();
    } catch (syncError) {
      setError(getApiErrorMessage(syncError, "Failed to sync STIX/TAXII simulation"));
    } finally {
      setIsSyncing(false);
    }
  };

  if (isLoading && !stats) {
    return (
      <div className="flex min-h-[320px] items-center justify-center rounded-2xl border border-slate-800 bg-slate-900/40">
        <div className="h-10 w-10 animate-spin rounded-full border-2 border-primary-500 border-t-transparent" />
      </div>
    );
  }

  if (error && !stats) {
    return (
      <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-6">
        <h3 className="text-lg font-semibold text-red-300">Unable to load STIX/TAXII dashboard</h3>
        <p className="mt-2 text-sm text-red-200/80">{error}</p>
        <button
          type="button"
          onClick={loadData}
          className="mt-4 rounded-lg bg-red-500/20 px-4 py-2 text-sm font-medium text-red-200 transition hover:bg-red-500/30"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!stats) {
    return null;
  }

  const taxiiEndpoints = [
    { label: "Discovery", path: "/api/v1/taxii2/" },
    { label: "API Root", path: "/api/v1/taxii2/root/" },
    { label: "Collections", path: "/api/v1/taxii2/root/collections/" },
    { label: "Collection Objects", path: "/api/v1/taxii2/root/collections/{id}/objects/" },
    { label: "STIX Bundle", path: "/api/v1/taxii2/root/collections/{id}/bundle/" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-xl font-semibold text-white">STIX / TAXII Simulation</h2>
          <p className="mt-1 text-sm text-slate-400">
            Simulated TAXII 2.1 server with STIX 2.1 threat intelligence feeds
          </p>
        </div>

        <div className="flex items-center gap-3">
          <span className="inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            TAXII {stats.taxii_version} / STIX {stats.stix_version}
          </span>
          <button
            type="button"
            onClick={handleSync}
            disabled={isSyncing}
            className={cn(
              "rounded-lg bg-primary-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-primary-400",
              "disabled:cursor-not-allowed disabled:opacity-60",
            )}
          >
            {isSyncing ? "Syncing..." : "Sync from IOC DB"}
          </button>
        </div>
      </div>

      {actionMessage ? (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
          {actionMessage}
        </div>
      ) : null}

      {error ? (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total Objects" value={stats.total_objects} accent="blue" />
        <StatCard label="Collections" value={stats.total_collections} accent="green" />
        <StatCard label="Indicators" value={stats.indicator_count} accent="amber" />
        <StatCard label="Threat Actors" value={stats.threat_actor_count} accent="red" />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5 lg:col-span-2">
          <h3 className="text-sm font-semibold text-white">STIX Object Distribution</h3>
          <p className="mt-1 text-xs text-slate-500">Breakdown by object type across all collections</p>
          <div className="mt-4">
            <StixObjectTypeChart distribution={stats.object_type_distribution} />
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
          <h3 className="text-sm font-semibold text-white">Feed Status</h3>
          <dl className="mt-4 space-y-3 text-sm">
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">API Root</dt>
              <dd className="font-mono text-xs text-primary-300">{stats.api_root}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">Last Synced</dt>
              <dd className="text-slate-300">
                {stats.last_synced_at ? formatDateTime(stats.last_synced_at) : "Never"}
              </dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">Malware Families</dt>
              <dd className="text-slate-300">{stats.malware_count}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">Attack Patterns</dt>
              <dd className="text-slate-300">{stats.attack_pattern_count}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-slate-500">Generated At</dt>
              <dd className="text-xs text-slate-400">{formatDateTime(stats.generated_at)}</dd>
            </div>
          </dl>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
        <h3 className="text-sm font-semibold text-white">TAXII Collections</h3>
        <p className="mt-1 text-xs text-slate-500">Available threat intelligence collections</p>
        <div className="mt-4">
          <TaxiiCollectionsTable collections={stats.collections} />
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
        <h3 className="text-sm font-semibold text-white">TAXII Endpoints</h3>
        <p className="mt-1 text-xs text-slate-500">Simulated TAXII 2.1 API paths for external consumers</p>
        <div className="mt-4">
          <DataTable
            columns={endpointColumns}
            data={taxiiEndpoints}
            rowKey={(row) => row.path}
          />
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">Recent STIX Objects</h3>
            <p className="mt-1 text-xs text-slate-500">Latest synchronized threat intelligence objects</p>
          </div>

          <div className="flex flex-wrap gap-2">
            {objectTypeFilters.map((filter) => (
              <button
                key={filter.id}
                type="button"
                onClick={() => {
                  setObjectTypeFilter(filter.id);
                  setPage(1);
                }}
                className={cn(
                  "rounded-lg px-3 py-1.5 text-xs font-medium transition",
                  objectTypeFilter === filter.id
                    ? "bg-primary-500/20 text-primary-300 ring-1 ring-primary-500/30"
                    : "bg-slate-800 text-slate-400 hover:text-slate-200",
                )}
              >
                {filter.label}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-4">
          <StixObjectsTable
            objects={objects}
            pagination={pagination}
            onPageChange={setPage}
            isLoading={isLoading}
          />
        </div>
      </div>
    </div>
  );
}
