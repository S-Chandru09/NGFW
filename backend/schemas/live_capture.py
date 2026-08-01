from typing import Any, Optional

from pydantic import BaseModel, Field


class LiveCaptureRequest(BaseModel):
  interface: Optional[str] = Field(default=None, max_length=64)
  bpf_filter: str = Field(default="ip or ip6", max_length=256)
  packet_count: int = Field(default=50, ge=1, le=5000)
  timeout_seconds: int = Field(default=30, ge=1, le=300)
  min_packets_before_predict: int = Field(default=2, ge=1, le=100)
  send_to_backend: bool = True
  session_id: Optional[str] = Field(default=None, max_length=100)


class LiveCaptureSummary(BaseModel):
  attack_counts: dict[str, int] = Field(default_factory=dict)
  threat_levels: dict[str, int] = Field(default_factory=dict)
  top_threat: Optional[dict[str, Any]] = None
  benign_flows: int = 0
  malicious_flows: int = 0


class LiveCaptureDetection(BaseModel):
  flow_id: str
  source_ip: Optional[str] = None
  destination_ip: Optional[str] = None
  source_port: Optional[int] = None
  destination_port: Optional[int] = None
  protocol: str
  total_packets: int
  prediction: dict[str, Any]
  detected_at: str


class LiveCaptureResponse(BaseModel):
  success: bool = True
  message: str
  session_id: str
  status: str
  interface: Optional[str] = None
  bpf_filter: str
  packets_processed: int
  predictions_generated: int
  threats_detected: int
  summary: LiveCaptureSummary
  detections: list[LiveCaptureDetection] = Field(default_factory=list)
  backend_delivery: Optional[dict[str, Any]] = None
  completed_at: str
  job_id: Optional[str] = None


class LiveCaptureCapabilitiesResponse(BaseModel):
  success: bool = True
  message: str
  enabled: bool
  default_interface: Optional[str] = None
  default_bpf_filter: str
  default_packet_count: int
  default_timeout_seconds: int
  send_to_backend: bool
  models_loaded: list[str] = Field(default_factory=list)
  notes: list[str] = Field(default_factory=list)
