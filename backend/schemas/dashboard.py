from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ProtocolTraffic(BaseModel):
  protocol: str
  flow_count: int
  total_bytes: int
  percentage: float


class HourlyTrafficPoint(BaseModel):
  hour: str
  flow_count: int
  total_bytes: int
  threat_count: int


class TrafficSummaryResponse(BaseModel):
  success: bool = True
  message: str
  total_flows: int
  total_bytes: int
  total_packets: int
  inbound_bytes: int
  outbound_bytes: int
  allowed_flows: int
  blocked_flows: int
  threat_flows: int
  unique_source_ips: int
  unique_destination_ips: int
  protocols: list[ProtocolTraffic]
  hourly_trend: list[HourlyTrafficPoint]
  period_hours: int
  generated_at: datetime


class AttackCountBreakdown(BaseModel):
  total_attacks: int
  attacks_today: int
  attacks_this_week: int
  attacks_this_month: int
  blocked_attacks: int
  active_alerts: int
  resolved_alerts: int
  critical_attacks: int
  high_attacks: int
  medium_attacks: int
  low_attacks: int


class AttackCountResponse(BaseModel):
  success: bool = True
  message: str
  data: AttackCountBreakdown
  generated_at: datetime


class ThreatLevelBreakdown(BaseModel):
  overall_score: float = Field(..., ge=0, le=100)
  overall_level: str
  critical_count: int
  high_count: int
  medium_count: int
  low_count: int
  risk_trend: str
  last_incident_at: Optional[datetime] = None


class ThreatLevelResponse(BaseModel):
  success: bool = True
  message: str
  data: ThreatLevelBreakdown
  generated_at: datetime


class AttackTypeItem(BaseModel):
  threat_type: str
  count: int
  percentage: float
  severity: str
  last_detected_at: Optional[datetime] = None


class ThreatAlertItem(BaseModel):
  alert_id: str
  threat_type: str
  severity: str
  status: str
  source_ip: Optional[str] = None
  destination_ip: Optional[str] = None
  flow_id: Optional[str] = None
  confidence: Optional[float] = None
  detected_at: datetime
  upload_id: Optional[str] = None
  original_filename: Optional[str] = None
  analysis_source: Optional[str] = None


class TopAttackTypesResponse(BaseModel):
  success: bool = True
  message: str
  total_attack_types: int
  top_attack_types: list[AttackTypeItem]
  period_hours: int
  generated_at: datetime


class DashboardKPI(BaseModel):
  label: str
  value: int | float | str
  unit: Optional[str] = None
  change_percentage: Optional[float] = None
  trend: Optional[str] = None


class DashboardStatisticsData(BaseModel):
  traffic_summary: TrafficSummaryResponse
  attack_count: AttackCountBreakdown
  threat_level: ThreatLevelBreakdown
  top_attack_types: list[AttackTypeItem]
  recent_threat_alerts: list[ThreatAlertItem] = Field(default_factory=list)
  kpis: list[DashboardKPI]
  firewall_rules_active: int
  firewall_rules_total: int
  trusted_devices: int
  total_devices: int
  zero_trust_enabled: bool


class DashboardStatisticsResponse(BaseModel):
  success: bool = True
  message: str
  data: DashboardStatisticsData
  generated_at: datetime
