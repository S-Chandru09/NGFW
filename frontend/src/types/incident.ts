import type { PaginationMeta } from "@/types/admin";

export type IncidentStatus =
  | "open"
  | "investigating"
  | "contained"
  | "resolved"
  | "closed";

export type IncidentSeverity = "info" | "warning" | "error" | "critical";

export type IncidentActionType =
  | "block_ip"
  | "kill_session"
  | "generate_report"
  | "status_change"
  | "note";

export interface IncidentAction {
  action_id: string;
  action_type: IncidentActionType;
  actor_id: string;
  actor_username: string;
  timestamp: string;
  details: Record<string, unknown>;
}

export interface Incident {
  incident_id: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  threat_type: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  affected_user_id: string | null;
  affected_device_id: string | null;
  assigned_to: string | null;
  trigger_source: string;
  trigger_reference_id: string | null;
  actions_taken: IncidentAction[];
  firewall_rule_ids: string[];
  session_ids_killed: string[];
  report_ids: string[];
  metadata: Record<string, unknown>;
  detected_at: string;
  resolved_at: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface IncidentStats {
  success: boolean;
  message: string;
  total_incidents: number;
  open_incidents: number;
  investigating_incidents: number;
  contained_incidents: number;
  resolved_incidents: number;
  critical_incidents: number;
  actions_taken_total: number;
  blocked_ips_total: number;
  sessions_killed_total: number;
  reports_generated_total: number;
  severity_distribution: Record<string, number>;
  status_distribution: Record<string, number>;
  generated_at: string;
}

export interface IncidentListResponse {
  success: boolean;
  message: string;
  items: Incident[];
  pagination: PaginationMeta;
}

export interface IncidentDetailResponse {
  success: boolean;
  message: string;
  incident: Incident;
}

export interface IncidentCreateResponse {
  success: boolean;
  message: string;
  incident: Incident;
}

export interface BlockIPResponse {
  success: boolean;
  message: string;
  incident: Incident;
  blocked_ip: string;
  firewall_rule_id: string;
  firewall_rule_name: string;
}

export interface KillSessionResponse {
  success: boolean;
  message: string;
  incident: Incident;
  sessions_killed: number;
  session_ids: string[];
  revoked_token_count: number;
}

export interface GenerateReportResponse {
  success: boolean;
  message: string;
  incident: Incident;
  report: {
    report_id: string;
    incident_id: string;
    title: string;
    format: string;
    generated_by: string;
    generated_at: string;
  };
}

export interface IncidentFormData {
  title: string;
  description: string;
  severity: IncidentSeverity;
  threat_type: string;
  source_ip: string;
  destination_ip: string;
  trigger_source: string;
}

export const EMPTY_INCIDENT_FORM: IncidentFormData = {
  title: "",
  description: "",
  severity: "warning",
  threat_type: "",
  source_ip: "",
  destination_ip: "",
  trigger_source: "manual",
};

export type IncidentDashboardTab = "list" | "severity" | "timeline";

export interface TimelineEvent {
  id: string;
  timestamp: string;
  title: string;
  description: string;
  type: "created" | "detected" | "resolved" | IncidentActionType;
  actor?: string;
  severity?: IncidentSeverity;
}
