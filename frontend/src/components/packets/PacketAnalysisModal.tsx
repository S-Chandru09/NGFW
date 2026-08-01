import StatusBadge, { threatLevelBadgeVariant } from "@/components/admin/StatusBadge";
import type { PacketAnalysisDetection, PacketAnalysisResponse } from "@/types/packetUpload";
import type { PacketUpload } from "@/types/packetUpload";
import { formatDateTime } from "@/utils";

interface PacketAnalysisModalProps {
  upload: PacketUpload | null;
  onClose: () => void;
}

function asAnalysisResponse(
  value: PacketAnalysisResponse | Record<string, unknown> | null | undefined,
): PacketAnalysisResponse | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  return value as PacketAnalysisResponse;
}

function formatConfidence(confidence: number | undefined): string {
  if (confidence === undefined || Number.isNaN(confidence)) {
    return "—";
  }

  return `${(confidence * 100).toFixed(1)}%`;
}

export default function PacketAnalysisModal({ upload, onClose }: PacketAnalysisModalProps) {
  if (!upload) {
    return null;
  }

  const analysis = asAnalysisResponse(upload.ai_engine_response);
  const summary = analysis?.summary;
  const detections = (analysis?.detections ?? []) as PacketAnalysisDetection[];
  const threatDetections = detections.filter((detection) => detection.prediction?.is_attack);
  const attackCounts = summary?.attack_counts ?? {};
  const backendDelivery = analysis?.backend_delivery;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4">
      <div className="max-h-[90vh] w-full max-w-4xl overflow-hidden rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl">
        <div className="flex items-start justify-between gap-4 border-b border-slate-800 px-6 py-5">
          <div>
            <h3 className="text-lg font-semibold text-white">PCAP Analysis Results</h3>
            <p className="mt-1 text-sm text-slate-400">{upload.original_filename}</p>
            <p className="mt-1 text-xs text-slate-500">Uploaded {formatDateTime(upload.created_at)}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 transition hover:bg-slate-800"
          >
            Close
          </button>
        </div>

        <div className="max-h-[calc(90vh-88px)] overflow-y-auto px-6 py-5">
          <div className="mb-5 flex flex-wrap gap-2">
            <StatusBadge label={upload.status} variant="info" />
            <StatusBadge label={upload.ai_engine_status} variant="muted" />
          </div>

          {upload.ai_engine_error ? (
            <div className="mb-5 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
              {upload.ai_engine_error}
            </div>
          ) : null}

          {!analysis ? (
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 px-4 py-8 text-center text-sm text-slate-400">
              No AI analysis results are available for this upload yet.
            </div>
          ) : (
            <div className="space-y-6">
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                  <p className="text-xs uppercase tracking-wide text-slate-500">Packets</p>
                  <p className="mt-2 text-2xl font-semibold text-white">
                    {(analysis.packets_processed ?? upload.packet_count).toLocaleString()}
                  </p>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                  <p className="text-xs uppercase tracking-wide text-slate-500">Flows analyzed</p>
                  <p className="mt-2 text-2xl font-semibold text-white">
                    {(analysis.flows_analyzed ?? 0).toLocaleString()}
                  </p>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                  <p className="text-xs uppercase tracking-wide text-slate-500">Threats detected</p>
                  <p className="mt-2 text-2xl font-semibold text-red-300">
                    {(analysis.threats_detected ?? summary?.malicious_flows ?? 0).toLocaleString()}
                  </p>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                  <p className="text-xs uppercase tracking-wide text-slate-500">Benign flows</p>
                  <p className="mt-2 text-2xl font-semibold text-emerald-300">
                    {(summary?.benign_flows ?? 0).toLocaleString()}
                  </p>
                </div>
              </div>

              {backendDelivery ? (
                <div
                  className={
                    backendDelivery.success === false
                      ? "rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200"
                      : "rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200"
                  }
                >
                  <p className="font-medium text-white">Dashboard integration</p>
                  {backendDelivery.enabled === false ? (
                    <p className="mt-1">Backend sender is disabled for this analysis run.</p>
                  ) : backendDelivery.success === false ? (
                    <p className="mt-1">
                      Failed to send flows to the dashboard backend
                      {backendDelivery.error ? `: ${backendDelivery.error}` : "."}
                    </p>
                  ) : (
                    <p className="mt-1">
                      Sent {(backendDelivery.sent_count ?? backendDelivery.total_flows ?? 0).toLocaleString()} flows
                      to the backend
                      {(backendDelivery.threat_flows_sent ?? 0) > 0
                        ? `, including ${backendDelivery.threat_flows_sent} threat flows that created dashboard alerts`
                        : ""}
                      . View them on the Dashboard or Threat Analytics pages.
                    </p>
                  )}
                </div>
              ) : null}

              {summary?.top_threat ? (
                <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
                  Top threat: <span className="font-semibold">{summary.top_threat.attack_label}</span>
                  {" "}({summary.top_threat.count} flows)
                </div>
              ) : null}

              {Object.keys(attackCounts).length > 0 ? (
                <div>
                  <h4 className="mb-3 text-sm font-medium text-slate-300">Attack breakdown</h4>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(attackCounts).map(([label, count]) => (
                      <StatusBadge key={label} label={`${label}: ${count}`} variant="danger" />
                    ))}
                  </div>
                </div>
              ) : null}

              <div>
                <h4 className="mb-3 text-sm font-medium text-slate-300">
                  Threat detections ({threatDetections.length})
                </h4>

                {threatDetections.length === 0 ? (
                  <div className="rounded-xl border border-slate-800 bg-slate-950/60 px-4 py-6 text-sm text-slate-400">
                    No malicious flows were detected in this PCAP.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {threatDetections.slice(0, 20).map((detection) => (
                      <div
                        key={detection.flow_id}
                        className="rounded-xl border border-slate-800 bg-slate-950/60 p-4"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-3">
                          <div>
                            <p className="font-medium text-white">{detection.prediction.attack_label}</p>
                            <p className="mt-1 text-xs text-slate-500">{detection.flow_id}</p>
                          </div>
                          <div className="flex flex-wrap items-center gap-2">
                            <StatusBadge
                              label={detection.prediction.threat_level}
                              variant={threatLevelBadgeVariant(detection.prediction.threat_level)}
                            />
                            <StatusBadge
                              label={formatConfidence(detection.prediction.confidence)}
                              variant="warning"
                            />
                          </div>
                        </div>
                        <p className="mt-3 text-sm text-slate-400">
                          {detection.source_ip ?? "unknown"}:{detection.source_port ?? "—"}
                          {" → "}
                          {detection.destination_ip ?? "unknown"}:{detection.destination_port ?? "—"}
                          {" · "}
                          {detection.protocol}
                          {" · "}
                          {detection.total_packets} packets
                        </p>
                      </div>
                    ))}
                    {threatDetections.length > 20 ? (
                      <p className="text-xs text-slate-500">
                        Showing first 20 of {threatDetections.length} threat detections.
                      </p>
                    ) : null}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
