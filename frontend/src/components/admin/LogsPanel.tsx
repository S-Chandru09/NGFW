import { useCallback, useEffect, useState } from "react";
import DataTable, { type Column } from "@/components/admin/DataTable";
import Pagination from "@/components/admin/Pagination";
import StatusBadge, { severityBadgeVariant } from "@/components/admin/StatusBadge";
import { getApiErrorMessage } from "@/services/apiClient";
import { deleteAuditLog, fetchAuditLogs, searchAuditLogs } from "@/services/adminService";
import type { AuditLog, LogEventType, LogSeverity, PaginationMeta } from "@/types/admin";
import { formatDateTime } from "@/utils";

export default function LogsPanel() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [pagination, setPagination] = useState<PaginationMeta | null>(null);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<LogSeverity | "">("");
  const [eventTypeFilter, setEventTypeFilter] = useState<LogEventType | "">("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadLogs = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const params = {
        page,
        page_size: 10,
        severity: severityFilter || undefined,
        event_type: eventTypeFilter || undefined,
      };

      const response = search.trim()
        ? await searchAuditLogs({ ...params, q: search.trim() })
        : await fetchAuditLogs(params);

      setLogs(response.items);
      setPagination(response.pagination);
    } catch (loadError) {
      setError(getApiErrorMessage(loadError, "Failed to load audit logs"));
    } finally {
      setIsLoading(false);
    }
  }, [eventTypeFilter, page, search, severityFilter]);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  const handleDelete = async (log: AuditLog) => {
    if (!window.confirm(`Delete log entry "${log.log_id}"?`)) {
      return;
    }

    try {
      await deleteAuditLog(log.id);
      await loadLogs();
    } catch (deleteError) {
      setError(getApiErrorMessage(deleteError, "Failed to delete log"));
    }
  };

  const columns: Column<AuditLog>[] = [
    {
      key: "timestamp",
      header: "Time",
      render: (log) => formatDateTime(log.created_at),
    },
    {
      key: "severity",
      header: "Severity",
      render: (log) => (
        <StatusBadge label={log.severity} variant={severityBadgeVariant(log.severity)} />
      ),
    },
    {
      key: "event_type",
      header: "Event",
      render: (log) => (
        <StatusBadge label={log.event_type} variant="info" />
      ),
    },
    {
      key: "message",
      header: "Message",
      className: "max-w-xs whitespace-normal",
      render: (log) => (
        <div>
          <p className="text-slate-200">{log.message}</p>
          {log.username ? (
            <p className="mt-0.5 text-xs text-slate-500">by {log.username}</p>
          ) : null}
        </div>
      ),
    },
    {
      key: "source",
      header: "Source",
      render: (log) => log.source,
    },
    {
      key: "ip",
      header: "IP",
      render: (log) => log.ip_address || "—",
    },
    {
      key: "actions",
      header: "Actions",
      render: (log) => (
        <button
          type="button"
          onClick={() => handleDelete(log)}
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
          <h3 className="text-lg font-semibold text-white">Audit Logs</h3>
          <p className="text-sm text-slate-400">Review security events, auth activity, and system actions</p>
        </div>

        <div className="flex flex-wrap gap-2">
          <input
            type="search"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setPage(1);
            }}
            placeholder="Search logs..."
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          />
          <select
            value={severityFilter}
            onChange={(event) => {
              setSeverityFilter(event.target.value as LogSeverity | "");
              setPage(1);
            }}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          >
            <option value="">All severities</option>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="error">Error</option>
            <option value="critical">Critical</option>
          </select>
          <select
            value={eventTypeFilter}
            onChange={(event) => {
              setEventTypeFilter(event.target.value as LogEventType | "");
              setPage(1);
            }}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          >
            <option value="">All events</option>
            <option value="auth">Auth</option>
            <option value="firewall">Firewall</option>
            <option value="threat">Threat</option>
            <option value="network">Network</option>
            <option value="system">System</option>
          </select>
          <button
            type="button"
            onClick={loadLogs}
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
        data={logs}
        rowKey={(log) => log.id}
        isLoading={isLoading}
        emptyMessage="No audit logs found."
      />

      {pagination ? (
        <Pagination pagination={pagination} onPageChange={setPage} />
      ) : null}
    </div>
  );
}
