import type { ReactNode } from "react";
import Pagination from "@/components/admin/Pagination";
import StatusBadge, { severityBadgeVariant } from "@/components/admin/StatusBadge";
import type { PaginationMeta } from "@/types/admin";
import type { Incident, IncidentSeverity, IncidentStatus } from "@/types/incident";
import { cn, formatDateTime } from "@/utils";

interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
}

function statusBadgeVariant(status: IncidentStatus) {
  switch (status) {
    case "open":
      return "danger" as const;
    case "investigating":
      return "warning" as const;
    case "contained":
      return "info" as const;
    case "resolved":
      return "success" as const;
    case "closed":
      return "muted" as const;
    default:
      return "default" as const;
  }
}

interface IncidentListTableProps {
  incidents: Incident[];
  pagination: PaginationMeta | null;
  selectedIncidentId: string | null;
  isLoading?: boolean;
  onPageChange: (page: number) => void;
  onSelect: (incident: Incident) => void;
}

const columns: Column<Incident>[] = [
  {
    key: "title",
    header: "Incident",
    render: (row) => (
      <div>
        <p className="font-medium text-white">{row.title}</p>
        <p className="mt-0.5 line-clamp-1 text-xs text-slate-500">{row.description}</p>
      </div>
    ),
  },
  {
    key: "severity",
    header: "Severity",
    render: (row) => (
      <StatusBadge label={row.severity} variant={severityBadgeVariant(row.severity)} />
    ),
  },
  {
    key: "status",
    header: "Status",
    render: (row) => (
      <StatusBadge label={row.status.replace("_", " ")} variant={statusBadgeVariant(row.status)} />
    ),
  },
  {
    key: "source_ip",
    header: "Source IP",
    render: (row) => (
      <span className="font-mono text-xs text-primary-300">{row.source_ip ?? "—"}</span>
    ),
  },
  {
    key: "actions",
    header: "Actions",
    render: (row) => <span className="text-slate-300">{row.actions_taken.length}</span>,
  },
  {
    key: "detected_at",
    header: "Detected",
    render: (row) => (
      <span className="text-xs text-slate-400">{formatDateTime(row.detected_at)}</span>
    ),
  },
];

interface IncidentListFiltersProps {
  search: string;
  statusFilter: IncidentStatus | "all";
  severityFilter: IncidentSeverity | "all";
  onSearchChange: (value: string) => void;
  onStatusChange: (value: IncidentStatus | "all") => void;
  onSeverityChange: (value: IncidentSeverity | "all") => void;
}

const inputClassName =
  "rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500";

export function IncidentListFilters({
  search,
  statusFilter,
  severityFilter,
  onSearchChange,
  onStatusChange,
  onSeverityChange,
}: IncidentListFiltersProps) {
  return (
    <div className="grid gap-3 md:grid-cols-3">
      <input
        type="search"
        value={search}
        onChange={(event) => onSearchChange(event.target.value)}
        placeholder="Search incidents..."
        className={inputClassName}
      />
      <select
        value={statusFilter}
        onChange={(event) => onStatusChange(event.target.value as IncidentStatus | "all")}
        className={inputClassName}
      >
        <option value="all">All statuses</option>
        <option value="open">Open</option>
        <option value="investigating">Investigating</option>
        <option value="contained">Contained</option>
        <option value="resolved">Resolved</option>
        <option value="closed">Closed</option>
      </select>
      <select
        value={severityFilter}
        onChange={(event) => onSeverityChange(event.target.value as IncidentSeverity | "all")}
        className={inputClassName}
      >
        <option value="all">All severities</option>
        <option value="critical">Critical</option>
        <option value="error">Error</option>
        <option value="warning">Warning</option>
        <option value="info">Info</option>
      </select>
    </div>
  );
}

export default function IncidentListTable({
  incidents,
  pagination,
  selectedIncidentId,
  isLoading,
  onPageChange,
  onSelect,
}: IncidentListTableProps) {
  return (
    <div className="space-y-4">
      <div className="overflow-hidden rounded-xl border border-slate-800">
        <table className="min-w-full divide-y divide-slate-800">
          <thead className="bg-slate-900/80">
            <tr className="text-left text-xs font-medium uppercase tracking-wide text-slate-500">
              {columns.map((column) => (
                <th key={column.key} className="px-4 py-3">
                  {column.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80 bg-slate-900/30">
            {isLoading ? (
              <tr>
                <td colSpan={columns.length} className="px-4 py-12 text-center">
                  <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-primary-500 border-t-transparent" />
                </td>
              </tr>
            ) : incidents.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-4 py-12 text-center text-sm text-slate-500">
                  No incidents found. Create one to begin incident response.
                </td>
              </tr>
            ) : (
              incidents.map((incident) => (
                <tr
                  key={incident.incident_id}
                  onClick={() => onSelect(incident)}
                  className={cn(
                    "cursor-pointer text-sm text-slate-300 transition hover:bg-slate-800/50",
                    selectedIncidentId === incident.incident_id && "bg-primary-500/10",
                  )}
                >
                  {columns.map((column) => (
                    <td key={column.key} className="px-4 py-3">
                      {column.render(incident)}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {pagination ? <Pagination pagination={pagination} onPageChange={onPageChange} /> : null}
    </div>
  );
}
