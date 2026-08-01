import StatusBadge, { severityBadgeVariant } from "@/components/admin/StatusBadge";
import type { ThreatAlertItem } from "@/types/dashboard";
import { formatDateTime } from "@/utils";

interface RecentThreatAlertsProps {
  alerts: ThreatAlertItem[];
  title?: string;
  description?: string;
  emptyMessage?: string;
}

function formatSourceLabel(alert: ThreatAlertItem): string {
  if (alert.analysis_source === "pcap_upload" && alert.original_filename) {
    return `PCAP: ${alert.original_filename}`;
  }

  if (alert.analysis_source === "pcap_upload") {
    return "PCAP upload";
  }

  return "AI engine";
}

export default function RecentThreatAlerts({
  alerts,
  title = "Recent Threat Alerts",
  description = "Latest detections from PCAP analysis and live monitoring",
  emptyMessage = "No threat alerts detected in this period.",
}: RecentThreatAlertsProps) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60">
      <div className="border-b border-slate-800 px-5 py-4">
        <h3 className="text-lg font-semibold text-white">{title}</h3>
        <p className="text-sm text-slate-500">{description}</p>
      </div>

      {alerts.length === 0 ? (
        <div className="px-5 py-8 text-sm text-slate-400">{emptyMessage}</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-800">
            <thead className="bg-slate-950/60">
              <tr>
                <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                  Threat
                </th>
                <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                  Source
                </th>
                <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                  Endpoint
                </th>
                <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                  Severity
                </th>
                <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-500">
                  Detected
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {alerts.map((alert) => (
                <tr key={alert.alert_id} className="hover:bg-slate-900/50">
                  <td className="px-5 py-4">
                    <p className="text-sm font-medium text-white">
                      {alert.threat_type.replace(/_/g, " ")}
                    </p>
                    <p className="mt-1 text-xs text-slate-500">{formatSourceLabel(alert)}</p>
                  </td>
                  <td className="px-5 py-4 text-sm text-slate-300">
                    {alert.source_ip ?? "—"}
                  </td>
                  <td className="px-5 py-4 text-sm text-slate-300">
                    {alert.destination_ip ?? "—"}
                  </td>
                  <td className="px-5 py-4">
                    <StatusBadge
                      label={alert.severity}
                      variant={severityBadgeVariant(alert.severity)}
                    />
                  </td>
                  <td className="px-5 py-4 text-sm text-slate-400">
                    {formatDateTime(alert.detected_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
