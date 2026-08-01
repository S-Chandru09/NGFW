from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from models.threat_intelligence import (
  HashReputationCreate,
  HashType,
  IOCType,
  IOCCreate,
  IOCPublic,
  IOCUpdate,
  IPReputationCreate,
  MaliciousDomainCreate,
  ThreatCategory,
  ThreatLevel,
)
from schemas.log import PaginationMeta


class IOCFilterParams(BaseModel):
  ioc_type: Optional[IOCType] = None
  hash_type: Optional[HashType] = None
  threat_level: Optional[ThreatLevel] = None
  is_malicious: Optional[bool] = None
  is_active: Optional[bool] = None
  source: Optional[str] = None
  country: Optional[str] = None
  threat_category: Optional[ThreatCategory] = None
  tag: Optional[str] = None
  min_reputation_score: Optional[int] = Field(default=None, ge=0, le=100)
  max_reputation_score: Optional[int] = Field(default=None, ge=0, le=100)


class IOCCreateResponse(BaseModel):
  success: bool = True
  message: str
  ioc: IOCPublic


class IOCDetailResponse(BaseModel):
  success: bool = True
  message: str
  ioc: IOCPublic


class IOCUpdateResponse(BaseModel):
  success: bool = True
  message: str
  ioc: IOCPublic


class IOCDeleteResponse(BaseModel):
  success: bool = True
  message: str
  ioc_id: str


class IOCListResponse(BaseModel):
  success: bool = True
  message: str
  items: list[IOCPublic]
  pagination: PaginationMeta


class IOCSearchResponse(BaseModel):
  success: bool = True
  message: str
  query: Optional[str] = None
  filters_applied: dict[str, Any]
  items: list[IOCPublic]
  pagination: PaginationMeta


class IOCReputationCheckResponse(BaseModel):
  success: bool = True
  message: str
  found: bool
  value: str
  ioc: Optional[IOCPublic] = None
  is_malicious: bool = False
  reputation_score: int = 0
  threat_level: ThreatLevel = ThreatLevel.SAFE


class IOCLookupRequest(BaseModel):
  values: list[str] = Field(..., min_length=1, max_length=100)


class IOCLookupResult(BaseModel):
  value: str
  found: bool
  is_malicious: bool = False
  reputation_score: int = 0
  threat_level: ThreatLevel = ThreatLevel.SAFE
  ioc: Optional[IOCPublic] = None


class IOCLookupResponse(BaseModel):
  success: bool = True
  message: str
  results: list[IOCLookupResult]


class ThreatIntelligenceStatsResponse(BaseModel):
  success: bool = True
  message: str
  total_iocs: int
  malicious_iocs: int
  active_iocs: int
  ip_count: int
  hash_count: int
  domain_count: int
  critical_threats: int
  high_threats: int
  generated_at: datetime


class IPReputationListResponse(BaseModel):
  success: bool = True
  message: str
  items: list[IOCPublic]
  pagination: PaginationMeta


class HashReputationListResponse(BaseModel):
  success: bool = True
  message: str
  items: list[IOCPublic]
  pagination: PaginationMeta


class MaliciousDomainListResponse(BaseModel):
  success: bool = True
  message: str
  items: list[IOCPublic]
  pagination: PaginationMeta
