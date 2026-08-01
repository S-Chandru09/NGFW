import StatusBadge, { severityBadgeVariant } from "@/components/admin/StatusBadge";
import type { Incident } from "@/types/incident";
import { formatDateTime } from "@/utils";

interface IncidentDetailPanelProps {
  incident: Incident | null;
  canRespond: boolean;
  isActionLoading: boolean;
  onBlockIP: () => void;
  onKillSession: () => void;
  onGenerateReport: () => void;
}

function statusBadgeVariant(status: string) {
  switch (status) {
    case "open":
      return "danger" as const;
    case "investigating":
      return "warning" as const;
    case "contained":
      return "info" as const;
    case "resolved":
      return "success" as const;
    default:
      return "muted" as const;
  }
}

export default function IncidentDetailPanel({
  incident,
  canRespond,
  isActionLoading,
  onBlockIP,
  onKillSession,
  onGenerateReport,
}: IncidentDetailPanelProps) {
  if (!incident) {
    return (
      <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
        <p className="text-sm text-slate-500">Select an incident to view details and response actions</p>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
      <div className="flex flex-wrap items-center gap-2">
        <StatusBadge label={incident.severity} variant={severityBadgeVariant(incident.severity)} />
        <StatusBadge label={incident.status.replace("_", " ")} variant={statusBadgeVariant(incident.status)} />
      </div>

      <h3 className="mt-4 text-lg font-semibold text-white">{incident.title}</h3>
      <p className="mt-2 text-sm text-slate-400">{incident.description}</p>

      <dl className="mt-5 grid gap-3 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-slate-500">Source IP</dt>
          <dd className="mt-0.5 font-mono text-primary-300">{incident.source_ip ?? "—"}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Threat Type</dt>
          <dd className="mt-0.5 text-slate-300">{incident.threat_type ?? "—"}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Detected</dt>
          <dd className="mt-0.5 text-slate-300">{formatDateTime(incident.detected_at)}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Trigger</dt>
          <dd className="mt-0.5 text-slate-300">{incident.trigger_source}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Firewall Rules</dt>
          <dd className="mt-0.5 text-slate-300">{incident.firewall_rule_ids.length}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Sessions Killed</dt>
          <dd className="mt-0.5 text-slate-300">{incident.session_ids_killed.length}</dd>
        </div>
      </dl>

      {canRespond ? (
        <div className="mt-6 flex flex-wrap gap-2 border-t border-slate-800 pt-5">
          <button
            type="button"
            onClick={onBlockIP}
            disabled={isActionLoading}
            className="rounded-lg bg-red-500/15 px-3 py-2 text-sm font-medium text-red-300 ring-1 ring-red-500/30 transition hover:bg-red-500/25 disabled:opacity-50"
          >
            Block IP
          </button>
          <button
            type="button"
            onClick={onKillSession}
            disabled={isActionLoading}
            className="rounded-lg bg-amber-500/15 px-3 py-2 text-sm font-medium text-amber-300 ring-1 ring-amber-500/30 transition hover:bg-amber-500/25 disabled:opacity-50"
          >
            Kill Session
          </button>
          <button
            type="button"
            onClick={onGenerateReport}
            disabled={isActionLoading}
            className="rounded-lg bg-primary-500/15 px-3 py-2 text-sm font-medium text-primary-300 ring-1 ring-primary-500/30 transition hover:bg-primary-500/25 disabled:opacity-50"
          >
            Generate Report
          </button>
        </div>
      ) : null}
    </div>
  );
}
