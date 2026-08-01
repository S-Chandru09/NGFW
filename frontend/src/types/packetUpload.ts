import type { PaginationMeta } from "@/types/admin";

export type PacketUploadStatus =
  | "pending"
  | "validating"
  | "validated"
  | "stored"
  | "processing"
  | "completed"
  | "failed";

export type AIEngineStatus =
  | "pending"
  | "queued"
  | "processing"
  | "completed"
  | "failed"
  | "skipped";

export interface PacketValidationResult {
  is_valid: boolean;
  file_type: string;
  packet_count: number;
  file_size: number;
  file_hash: string;
  errors: string[];
  warnings: string[];
}

export interface PacketAnalysisSummary {
  attack_counts?: Record<string, number>;
  threat_levels?: Record<string, number>;
  top_threat?: {
    attack_label: string;
    count: number;
  };
  benign_flows?: number;
  malicious_flows?: number;
}

export interface PacketAnalysisPrediction {
  attack_label: string;
  confidence: number;
  is_attack: boolean;
  threat_level: string;
}

export interface PacketAnalysisDetection {
  flow_id: string;
  source_ip?: string | null;
  destination_ip?: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  protocol: string;
  total_packets: number;
  prediction: PacketAnalysisPrediction;
}

export interface PacketAnalysisResponse {
  status?: string;
  packets_processed?: number;
  flows_analyzed?: number;
  flows_generated?: number;
  threats_detected?: number;
  summary?: PacketAnalysisSummary;
  detections?: PacketAnalysisDetection[];
  backend_delivery?: PacketBackendDelivery | null;
  message?: string;
}

export interface PacketBackendDelivery {
  enabled?: boolean;
  success?: boolean;
  message?: string;
  total_flows?: number;
  sent_count?: number;
  failed_count?: number;
  threat_flows_sent?: number;
  benign_flows_sent?: number;
  error?: string;
}

export interface PacketUpload {
  id: string;
  upload_id: string;
  original_filename: string;
  stored_filename: string;
  file_path: string;
  file_size: number;
  file_hash: string;
  file_type: string;
  packet_count: number;
  status: PacketUploadStatus;
  validation_result: PacketValidationResult;
  ai_engine_status: AIEngineStatus;
  ai_engine_job_id?: string | null;
  ai_engine_response?: PacketAnalysisResponse | Record<string, unknown> | null;
  ai_engine_error?: string | null;
  uploaded_by?: string | null;
  created_at: string;
  updated_at: string;
}

export interface PacketUploadListResponse {
  success: boolean;
  message: string;
  items: PacketUpload[];
  pagination: PaginationMeta;
}

export interface PacketUploadResponse {
  success: boolean;
  message: string;
  upload: PacketUpload;
}

export interface PacketUploadStatusResponse {
  success: boolean;
  message: string;
  upload_id: string;
  status: PacketUploadStatus;
  ai_engine_status: AIEngineStatus;
  ai_engine_job_id?: string | null;
  ai_engine_response?: PacketAnalysisResponse | Record<string, unknown> | null;
  ai_engine_error?: string | null;
  updated_at: string;
}
