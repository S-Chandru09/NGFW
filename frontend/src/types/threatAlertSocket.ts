export type ThreatAlertSocketStatus = "idle" | "connecting" | "connected" | "disconnected" | "error";

export interface ThreatAlertMessage {
  alert_id: string;
  threat_type: string;
  severity: string;
  status?: string;
  source_ip?: string | null;
  destination_ip?: string | null;
  flow_id?: string | null;
  confidence?: number | null;
  detected_at?: string;
  analysis_source?: string | null;
  upload_id?: string | null;
  original_filename?: string | null;
  session_id?: string | null;
}

export interface ThreatAlertSocketMessage {
  type: "threat_alert" | "connection_ack" | "pong";
  data: ThreatAlertMessage & {
    message?: string;
    subscribed_events?: string[];
  };
}
