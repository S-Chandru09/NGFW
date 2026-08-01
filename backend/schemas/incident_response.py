from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from models.firewall_engine import AutomaticRuleAction
from models.incident_response import IncidentPublic, IncidentSeverity, IncidentStatus
from schemas.log import PaginationMeta


class IncidentCreateRequest(BaseModel):
  title: str = Field(..., min_length=3, max_length=200)
  description: str = Field(..., min_length=3, max_length=5000)
  severity: IncidentSeverity = IncidentSeverity.WARNING
  threat_type: Optional[str] = Field(default=None, max_length=100)
  source_ip: Optional[str] = Field(default=None, max_length=45)
  destination_ip: Optional[str] = Field(default=None, max_length=45)
  affected_user_id: Optional[str] = None
  affected_device_id: Optional[str] = None
  assigned_to: Optional[str] = None
  trigger_source: str = Field(default="manual", max_length=100)
  trigger_reference_id: Optional[str] = Field(default=None, max_length=100)
  metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentUpdateRequest(BaseModel):
  title: Optional[str] = Field(default=None, min_length=3, max_length=200)
  description: Optional[str] = Field(default=None, min_length=3, max_length=5000)
  severity: Optional[IncidentSeverity] = None
  status: Optional[IncidentStatus] = None
  threat_type: Optional[str] = Field(default=None, max_length=100)
  source_ip: Optional[str] = Field(default=None, max_length=45)
  destination_ip: Optional[str] = Field(default=None, max_length=45)
  affected_user_id: Optional[str] = None
  affected_device_id: Optional[str] = None
  assigned_to: Optional[str] = None
  metadata: Optional[dict[str, Any]] = None


class BlockIPRequest(BaseModel):
  ip_address: Optional[str] = Field(default=None, max_length=45)
  action: AutomaticRuleAction = AutomaticRuleAction.BLACKLIST
  duration_hours: int = Field(default=24, ge=1, le=168)
  reason: Optional[str] = Field(default=None, max_length=500)
  priority: int = Field(default=400, ge=1, le=1000)


class KillSessionRequest(BaseModel):
  session_id: Optional[str] = Field(default=None, max_length=100)
  user_id: Optional[str] = None
  ip_address: Optional[str] = Field(default=None, max_length=45)
  kill_all_for_user: bool = False
  reason: Optional[str] = Field(default=None, max_length=500)


class GenerateReportRequest(BaseModel):
  include_audit_logs: bool = True
  include_firewall_rules: bool = True
  include_ioc_enrichment: bool = True
  include_session_history: bool = True
  notes: Optional[str] = Field(default=None, max_length=2000)


class IncidentReportSection(BaseModel):
  title: str
  data: dict[str, Any]


class IncidentReportContent(BaseModel):
  incident: IncidentPublic
  summary: dict[str, Any]
  sections: list[IncidentReportSection] = Field(default_factory=list)
  recommendations: list[str] = Field(default_factory=list)


class IncidentReportPublic(BaseModel):
  report_id: str
  incident_id: str
  title: str
  format: str = "json"
  content: IncidentReportContent
  generated_by: str
  generated_at: datetime


class IncidentCreateResponse(BaseModel):
  success: bool = True
  message: str
  incident: IncidentPublic


class IncidentDetailResponse(BaseModel):
  success: bool = True
  message: str
  incident: IncidentPublic


class IncidentListResponse(BaseModel):
  success: bool = True
  message: str
  items: list[IncidentPublic]
  pagination: PaginationMeta


class IncidentUpdateResponse(BaseModel):
  success: bool = True
  message: str
  incident: IncidentPublic


class BlockIPResponse(BaseModel):
  success: bool = True
  message: str
  incident: IncidentPublic
  blocked_ip: str
  firewall_rule_id: str
  firewall_rule_name: str


class KillSessionResponse(BaseModel):
  success: bool = True
  message: str
  incident: IncidentPublic
  sessions_killed: int
  session_ids: list[str]
  revoked_token_count: int


class GenerateReportResponse(BaseModel):
  success: bool = True
  message: str
  incident: IncidentPublic
  report: IncidentReportPublic


class IncidentStatsResponse(BaseModel):
  success: bool = True
  message: str
  total_incidents: int
  open_incidents: int
  investigating_incidents: int
  contained_incidents: int
  resolved_incidents: int
  critical_incidents: int
  actions_taken_total: int
  blocked_ips_total: int
  sessions_killed_total: int
  reports_generated_total: int
  severity_distribution: dict[str, int]
  status_distribution: dict[str, int]
  generated_at: datetime
