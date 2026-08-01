import StatusBadge, { severityBadgeVariant } from "@/components/admin/StatusBadge";
import type { ThreatAlertMessage, ThreatAlertSocketStatus } from "@/types/threatAlertSocket";
import { formatDateTime } from "@/utils";

interface ThreatAlertToastStackProps {
  alerts: ThreatAlertMessage[];
  status: ThreatAlertSocketStatus;
  onDismiss: (alertId: string) => void;
}

function formatSourceLabel(alert: ThreatAlertMessage): string {
  if (alert.analysis_source === "pcap_upload" && alert.original_filename) {
    return `PCAP: ${alert.original_filename}`;
  }

  if (alert.analysis_source === "live_capture") {
    return "Live capture";
  }

  return "AI engine";
}

export default function ThreatAlertToastStack({
  alerts,
  status,
  onDismiss,
}: ThreatAlertToastStackProps) {
  if (alerts.length === 0) {
    return null;
  }

  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-full max-w-sm flex-col gap-3">
      <div className="pointer-events-auto flex items-center justify-between rounded-full border border-slate-700 bg-slate-900/95 px-3 py-1.5 text-xs text-slate-300 shadow-lg backdrop-blur">
        <span>Real-time alerts</span>
        <StatusBadge
          label={status === "connected" ? "Live" : status}
          variant={status === "connected" ? "success" : "warning"}
        />
      </div>

      {alerts.map((alert) => (
        <div
          key={alert.alert_id}
          className="pointer-events-auto rounded-2xl border border-red-500/30 bg-slate-900/95 p-4 shadow-2xl backdrop-blur"
        >
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-sm font-semibold text-white">
                {alert.threat_type.replace(/_/g, " ")}
              </p>
              <p className="mt-1 text-xs text-slate-400">{formatSourceLabel(alert)}</p>
            </div>
            <button
              type="button"
              onClick={() => onDismiss(alert.alert_id)}
              className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
            >
              Dismiss
            </button>
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-2">
            <StatusBadge
              label={alert.severity}
              variant={severityBadgeVariant(alert.severity)}
            />
            {alert.confidence !== undefined && alert.confidence !== null ? (
              <StatusBadge
                label={`${(alert.confidence * 100).toFixed(1)}%`}
                variant="warning"
              />
            ) : null}
          </div>

          <p className="mt-3 text-xs text-slate-400">
            {alert.source_ip ?? "unknown"} → {alert.destination_ip ?? "unknown"}
          </p>
          {alert.detected_at ? (
            <p className="mt-1 text-xs text-slate-500">{formatDateTime(alert.detected_at)}</p>
          ) : null}
        </div>
      ))}
    </div>
  );
}
