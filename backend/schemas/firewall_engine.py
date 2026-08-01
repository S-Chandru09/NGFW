from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from models.firewall_engine import AutomaticRuleAction, AutomaticRuleTrigger
from models.firewall_rule import FirewallProtocol, FirewallRulePublic


class FirewallFlowRequest(BaseModel):
  source_ip: str = Field(..., min_length=3, max_length=45)
  destination_ip: str = Field(..., min_length=3, max_length=45)
  source_port: Optional[int] = Field(default=None, ge=1, le=65535)
  destination_port: Optional[int] = Field(default=None, ge=1, le=65535)
  protocol: FirewallProtocol = FirewallProtocol.ANY
  flow_id: Optional[str] = None


class FirewallFlowBatchRequest(BaseModel):
  flows: list[FirewallFlowRequest] = Field(..., min_length=1, max_length=100)


class FirewallMatchDetail(BaseModel):
  rule_id: Optional[str] = None
  rule_name: Optional[str] = None
  action: str
  priority: Optional[int] = None
  matched_on: list[str] = Field(default_factory=list)


class FirewallEvaluationResult(BaseModel):
  flow_id: Optional[str] = None
  source_ip: str
  destination_ip: str
  source_port: Optional[int] = None
  destination_port: Optional[int] = None
  protocol: FirewallProtocol
  source_country: Optional[str] = None
  destination_country: Optional[str] = None
  decision: str
  is_allowed: bool
  matched_rule: Optional[FirewallRulePublic] = None
  match_details: list[FirewallMatchDetail] = Field(default_factory=list)
  evaluated_at: datetime


class FirewallEvaluationResponse(BaseModel):
  success: bool = True
  message: str
  result: FirewallEvaluationResult


class FirewallBatchEvaluationResponse(BaseModel):
  success: bool = True
  message: str
  results: list[FirewallEvaluationResult]
  allowed_count: int
  blocked_count: int


class CountrySimulationRequest(BaseModel):
  country_code: str = Field(..., min_length=2, max_length=2)
  destination_ip: str = Field(default="10.0.0.1", min_length=3, max_length=45)
  source_ip: Optional[str] = Field(default=None, min_length=3, max_length=45)
  source_port: Optional[int] = Field(default=None, ge=1, le=65535)
  destination_port: Optional[int] = Field(default=443, ge=1, le=65535)
  protocol: FirewallProtocol = FirewallProtocol.TCP
  create_country_rule: bool = False


class CountrySimulationResponse(BaseModel):
  success: bool = True
  message: str
  country_code: str
  country_name: str
  simulated_source_ip: str
  evaluation: FirewallEvaluationResult
  auto_rule_created: Optional[FirewallRulePublic] = None


class AutomaticRuleRequest(BaseModel):
  trigger: AutomaticRuleTrigger
  source_ip: Optional[str] = Field(default=None, max_length=45)
  destination_ip: Optional[str] = Field(default=None, max_length=45)
  country_code: Optional[str] = Field(default=None, min_length=2, max_length=2)
  threat_type: Optional[str] = Field(default=None, max_length=100)
  trust_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
  reference_id: Optional[str] = Field(default=None, max_length=100)
  action: AutomaticRuleAction = AutomaticRuleAction.TEMPORARY_BLOCK
  duration_hours: int = Field(default=24, ge=1, le=168)
  priority: int = Field(default=300, ge=1, le=1000)


class AutomaticRuleResponse(BaseModel):
  success: bool = True
  message: str
  rule: FirewallRulePublic
  trigger: AutomaticRuleTrigger
  evaluation_preview: Optional[FirewallEvaluationResult] = None


class SupportedCountryResponse(BaseModel):
  success: bool = True
  message: str
  countries: list[dict[str, str]]
