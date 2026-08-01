export interface LiveCaptureRequest {
  interface?: string | null;
  bpf_filter?: string;
  packet_count?: number;
  timeout_seconds?: number;
  min_packets_before_predict?: number;
  send_to_backend?: boolean;
  session_id?: string | null;
}

export interface LiveCaptureSummary {
  attack_counts?: Record<string, number>;
  threat_levels?: Record<string, number>;
  top_threat?: {
    attack_label: string;
    count: number;
  };
  benign_flows?: number;
  malicious_flows?: number;
}

export interface LiveCaptureDetection {
  flow_id: string;
  source_ip?: string | null;
  destination_ip?: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  protocol: string;
  total_packets: number;
  prediction: {
    attack_label: string;
    confidence: number;
    is_attack: boolean;
    threat_level: string;
  };
  detected_at: string;
}

export interface LiveCaptureResponse {
  success: boolean;
  message: string;
  session_id: string;
  status: string;
  interface?: string | null;
  bpf_filter: string;
  packets_processed: number;
  predictions_generated: number;
  threats_detected: number;
  summary: LiveCaptureSummary;
  detections: LiveCaptureDetection[];
  backend_delivery?: Record<string, unknown> | null;
  completed_at: string;
  job_id?: string | null;
}

export interface LiveCaptureCapabilitiesResponse {
  success: boolean;
  message: string;
  enabled: boolean;
  default_interface?: string | null;
  default_bpf_filter: string;
  default_packet_count: number;
  default_timeout_seconds: number;
  send_to_backend: boolean;
  models_loaded: string[];
  notes: string[];
}
