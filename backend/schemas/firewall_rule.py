from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from models.firewall_rule import (
  FirewallProtocol,
  FirewallRuleAction,
  FirewallRuleCreate,
  FirewallRulePublic,
  FirewallRuleUpdate,
)
from schemas.log import PaginationMeta


class FirewallRuleFilterParams(BaseModel):
  action: Optional[FirewallRuleAction] = None
  protocol: Optional[FirewallProtocol] = None
  source_ip: Optional[str] = None
  destination_ip: Optional[str] = None
  is_enabled: Optional[bool] = None
  is_expired: Optional[bool] = None
  created_by: Optional[str] = None


class FirewallRuleListResponse(BaseModel):
  success: bool = True
  message: str
  items: list[FirewallRulePublic]
  pagination: PaginationMeta


class FirewallRuleDetailResponse(BaseModel):
  success: bool = True
  message: str
  rule: FirewallRulePublic


class FirewallRuleCreateResponse(BaseModel):
  success: bool = True
  message: str
  rule: FirewallRulePublic


class FirewallRuleUpdateResponse(BaseModel):
  success: bool = True
  message: str
  rule: FirewallRulePublic


class FirewallRuleDeleteResponse(BaseModel):
  success: bool = True
  message: str
  rule_id: str


class FirewallRuleActionSummary(BaseModel):
  action: FirewallRuleAction
  total: int
  enabled: int
  disabled: int
  expired: int


class FirewallRuleStatsResponse(BaseModel):
  success: bool = True
  message: str
  total_rules: int
  enabled_rules: int
  disabled_rules: int
  expired_rules: int
  action_summary: list[FirewallRuleActionSummary]


class AllowRuleCreate(FirewallRuleCreate):
  action: FirewallRuleAction = FirewallRuleAction.ALLOW
  expires_at: Optional[datetime] = None


class BlockRuleCreate(FirewallRuleCreate):
  action: FirewallRuleAction = FirewallRuleAction.BLOCK
  expires_at: Optional[datetime] = None


class WhitelistRuleCreate(FirewallRuleCreate):
  action: FirewallRuleAction = FirewallRuleAction.WHITELIST
  expires_at: Optional[datetime] = None


class BlacklistRuleCreate(FirewallRuleCreate):
  action: FirewallRuleAction = FirewallRuleAction.BLACKLIST
  expires_at: Optional[datetime] = None


class TemporaryBlockRuleCreate(BaseModel):
  name: str = Field(..., min_length=3, max_length=100)
  description: Optional[str] = Field(default=None, max_length=500)
  source_ip: Optional[str] = Field(default=None, max_length=45)
  destination_ip: Optional[str] = Field(default=None, max_length=45)
  source_port: Optional[int] = Field(default=None, ge=1, le=65535)
  destination_port: Optional[int] = Field(default=None, ge=1, le=65535)
  protocol: FirewallProtocol = FirewallProtocol.ANY
  priority: int = Field(default=200, ge=1, le=1000)
  is_enabled: bool = True
  expires_at: datetime

  def to_firewall_rule_create(self) -> FirewallRuleCreate:
    return FirewallRuleCreate(
      name=self.name,
      description=self.description,
      action=FirewallRuleAction.TEMPORARY_BLOCK,
      source_ip=self.source_ip,
      destination_ip=self.destination_ip,
      source_port=self.source_port,
      destination_port=self.destination_port,
      protocol=self.protocol,
      priority=self.priority,
      is_enabled=self.is_enabled,
      expires_at=self.expires_at,
    )
