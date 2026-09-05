from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class NetworkFlowIngestRequest(BaseModel):
  flow_id: str = Field(..., min_length=1, max_length=255)
  source_ip: Optional[str] = Field(default=None, max_length=45)
  destination_ip: Optional[str] = Field(default=None, max_length=45)
  source_mac: Optional[str] = Field(default=None, max_length=32)
  destination_mac: Optional[str] = Field(default=None, max_length=32)
  source_port: Optional[int] = Field(default=None, ge=0, le=65535)
  destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
  protocol: Optional[str] = Field(default=None, max_length=32)
  captured_at: Optional[datetime | str] = None
  flow_start_time: Optional[datetime | str] = None
  flow_end_time: Optional[datetime | str] = None
  flow_duration: Optional[float] = None
  flow_packets_s: Optional[float] = None
  flow_bytes_s: Optional[float] = None
  total_packets: Optional[int] = Field(default=None, ge=0)
  total_bytes: Optional[int] = Field(default=None, ge=0)
  total_fwd_packets: Optional[int] = Field(default=None, ge=0)
  total_backward_packets: Optional[int] = Field(default=None, ge=0)
  total_length_of_fwd_packets: Optional[int] = Field(default=None, ge=0)
  total_length_of_bwd_packets: Optional[int] = Field(default=None, ge=0)
  packet_count: Optional[int] = Field(default=None, ge=0)
  bytes_sent: Optional[int] = Field(default=None, ge=0)
  bytes_received: Optional[int] = Field(default=None, ge=0)
  action: Optional[str] = Field(default=None, max_length=32)
  features: dict[str, Any] = Field(default_factory=dict)
  metadata: dict[str, Any] = Field(default_factory=dict)
  prediction: Optional[dict[str, Any]] = None
  is_threat: bool = False
  threat_label: Optional[str] = Field(default=None, max_length=100)
  threat_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
  user_id: Optional[str] = Field(default=None, max_length=64)
  device_id: Optional[str] = Field(default=None, max_length=64)
  uploaded_by: Optional[str] = Field(default=None, max_length=64)


class NetworkFlowBatchIngestRequest(BaseModel):
  flows: list[NetworkFlowIngestRequest] = Field(..., min_length=1)
  metadata: dict[str, Any] = Field(default_factory=dict)


class NetworkFlowIngestResponse(BaseModel):
  success: bool = True
  message: str
  flow_id: str
  is_threat: bool = False
  created: bool = True


class NetworkFlowBatchIngestResponse(BaseModel):
  success: bool = True
  message: str
  total_flows: int
  ingested_count: int
  threat_count: int
