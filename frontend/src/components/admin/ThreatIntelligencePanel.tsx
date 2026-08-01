import { useCallback, useEffect, useState } from "react";
import DataTable, { type Column } from "@/components/admin/DataTable";
import Pagination from "@/components/admin/Pagination";
import StatusBadge, { threatLevelBadgeVariant } from "@/components/admin/StatusBadge";
import { getApiErrorMessage } from "@/services/apiClient";
import { deleteThreatIOC, fetchThreatIOCs, searchThreatIOCs } from "@/services/adminService";
import type { IOCType, PaginationMeta, ThreatIOC, ThreatIntelLevel } from "@/types/admin";
import { formatDateTime } from "@/utils";

export default function ThreatIntelligencePanel() {
  const [iocs, setIocs] = useState<ThreatIOC[]>([]);
  const [pagination, setPagination] = useState<PaginationMeta | null>(null);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<IOCType | "">("");
  const [levelFilter, setLevelFilter] = useState<ThreatIntelLevel | "">("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadIOCs = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const params = {
        page,
        page_size: 10,
        ioc_type: typeFilter || undefined,
        threat_level: levelFilter || undefined,
      };

      const response = search.trim()
        ? await searchThreatIOCs({ ...params, q: search.trim() })
        : await fetchThreatIOCs(params);

      setIocs(response.items);
      setPagination(response.pagination);
    } catch (loadError) {
      setError(getApiErrorMessage(loadError, "Failed to load threat intelligence"));
    } finally {
      setIsLoading(false);
    }
  }, [levelFilter, page, search, typeFilter]);

  useEffect(() => {
    loadIOCs();
  }, [loadIOCs]);

  const handleDelete = async (ioc: ThreatIOC) => {
    if (!window.confirm(`Delete IOC "${ioc.value}"?`)) {
      return;
    }

    try {
      await deleteThreatIOC(ioc.id);
      await loadIOCs();
    } catch (deleteError) {
      setError(getApiErrorMessage(deleteError, "Failed to delete IOC"));
    }
  };

  const columns: Column<ThreatIOC>[] = [
    {
      key: "value",
      header: "IOC",
      render: (ioc) => (
        <div>
          <p className="max-w-[200px] truncate font-medium text-white" title={ioc.value}>
            {ioc.value}
          </p>
          <p className="text-xs text-slate-500">{ioc.ioc_id}</p>
        </div>
      ),
    },
    {
      key: "type",
      header: "Type",
      render: (ioc) => <StatusBadge label={ioc.ioc_type} variant="info" />,
    },
    {
      key: "threat_level",
      header: "Threat Level",
      render: (ioc) => (
        <StatusBadge
          label={ioc.threat_level}
          variant={threatLevelBadgeVariant(ioc.threat_level)}
        />
      ),
    },
    {
      key: "reputation",
      header: "Reputation",
      render: (ioc) => (
        <div>
          <p className="font-medium">{ioc.reputation_score}/100</p>
          <StatusBadge
            label={ioc.is_malicious ? "Malicious" : "Benign"}
            variant={ioc.is_malicious ? "danger" : "success"}
          />
        </div>
      ),
    },
    {
      key: "source",
      header: "Source",
      render: (ioc) => ioc.source,
    },
    {
      key: "hits",
      header: "Hits",
      render: (ioc) => ioc.hit_count,
    },
    {
      key: "last_seen",
      header: "Last Seen",
      render: (ioc) => formatDateTime(ioc.last_seen_at),
    },
    {
      key: "actions",
      header: "Actions",
      render: (ioc) => (
        <button
          type="button"
          onClick={() => handleDelete(ioc)}
          className="rounded-md border border-red-500/30 px-2 py-1 text-xs text-red-300 transition hover:bg-red-500/10"
        >
          Delete
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h3 className="text-lg font-semibold text-white">Threat Intelligence</h3>
          <p className="text-sm text-slate-400">Browse and manage IOC database entries</p>
        </div>

        <div className="flex flex-wrap gap-2">
          <input
            type="search"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setPage(1);
            }}
            placeholder="Search IOCs..."
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          />
          <select
            value={typeFilter}
            onChange={(event) => {
              setTypeFilter(event.target.value as IOCType | "");
              setPage(1);
            }}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          >
            <option value="">All types</option>
            <option value="ip">IP</option>
            <option value="domain">Domain</option>
            <option value="hash">Hash</option>
            <option value="url">URL</option>
            <option value="email">Email</option>
          </select>
          <select
            value={levelFilter}
            onChange={(event) => {
              setLevelFilter(event.target.value as ThreatIntelLevel | "");
              setPage(1);
            }}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          >
            <option value="">All levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="safe">Safe</option>
          </select>
          <button
            type="button"
            onClick={loadIOCs}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 transition hover:bg-slate-800"
          >
            Refresh
          </button>
        </div>
      </div>

      {error ? (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}

      <DataTable
        columns={columns}
        data={iocs}
        rowKey={(ioc) => ioc.id}
        isLoading={isLoading}
        emptyMessage="No IOC entries found."
      />

      {pagination ? (
        <Pagination pagination={pagination} onPageChange={setPage} />
      ) : null}
    </div>
  );
}
