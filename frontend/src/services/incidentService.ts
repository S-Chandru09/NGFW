import { apiService } from "@/services/api";
import type {
  BlockIPResponse,
  GenerateReportResponse,
  Incident,
  IncidentCreateResponse,
  IncidentDetailResponse,
  IncidentFormData,
  IncidentListResponse,
  IncidentSeverity,
  IncidentStats,
  IncidentStatus,
  KillSessionResponse,
} from "@/types/incident";

export async function fetchIncidentStats() {
  return apiService.get<IncidentStats>("/incident-response/stats");
}

export async function fetchIncidents(params: {
  page?: number;
  page_size?: number;
  status?: IncidentStatus;
  severity?: IncidentSeverity;
  search?: string;
}) {
  return apiService.get<IncidentListResponse>("/incident-response/incidents", { params });
}

export async function fetchIncident(incidentId: string) {
  return apiService.get<IncidentDetailResponse>(`/incident-response/incidents/${incidentId}`);
}

export async function createIncident(form: IncidentFormData) {
  return apiService.post<IncidentCreateResponse>("/incident-response/incidents", {
    title: form.title.trim(),
    description: form.description.trim(),
    severity: form.severity,
    threat_type: form.threat_type.trim() || undefined,
    source_ip: form.source_ip.trim() || undefined,
    destination_ip: form.destination_ip.trim() || undefined,
    trigger_source: form.trigger_source.trim() || "manual",
  });
}

export async function updateIncident(
  incidentId: string,
  updates: Partial<Pick<Incident, "status" | "severity" | "title" | "description">>,
) {
  return apiService.patch<IncidentDetailResponse>(`/incident-response/incidents/${incidentId}`, updates);
}

export async function blockIncidentIP(
  incidentId: string,
  payload: {
    ip_address?: string;
    action?: "block" | "blacklist" | "temporary_block";
    duration_hours?: number;
    reason?: string;
  } = {},
) {
  return apiService.post<BlockIPResponse>(`/incident-response/incidents/${incidentId}/block-ip`, payload);
}

export async function killIncidentSession(
  incidentId: string,
  payload: {
    session_id?: string;
    user_id?: string;
    ip_address?: string;
    kill_all_for_user?: boolean;
    reason?: string;
  } = {},
) {
  return apiService.post<KillSessionResponse>(
    `/incident-response/incidents/${incidentId}/kill-session`,
    payload,
  );
}

export async function generateIncidentReport(
  incidentId: string,
  payload: {
    include_audit_logs?: boolean;
    include_firewall_rules?: boolean;
    include_ioc_enrichment?: boolean;
    include_session_history?: boolean;
    notes?: string;
  } = {},
) {
  return apiService.post<GenerateReportResponse>(
    `/incident-response/incidents/${incidentId}/report`,
    payload,
  );
}
