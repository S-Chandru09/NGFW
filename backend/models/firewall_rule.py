from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional
from uuid import uuid4

from bson import ObjectId
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator, model_validator

from core.firewall_wildcards import (
  normalize_ip_constraint,
  normalize_port_constraint,
  normalize_protocol_constraint,
)


class FirewallRuleAction(str, Enum):
  ALLOW = "allow"
  BLOCK = "block"
  WHITELIST = "whitelist"
  BLACKLIST = "blacklist"
  TEMPORARY_BLOCK = "temporary_block"


class FirewallProtocol(str, Enum):
  TCP = "tcp"
  UDP = "udp"
  ICMP = "icmp"
  ANY = "any"


def validate_object_id(value: Any) -> str:
  if isinstance(value, ObjectId):
    return str(value)

  if isinstance(value, str) and ObjectId.is_valid(value):
    return value

  raise ValueError("Invalid ObjectId")


PyObjectId = Annotated[str, BeforeValidator(validate_object_id)]


class FirewallRuleBase(BaseModel):
  name: str = Field(..., min_length=3, max_length=100)
  description: Optional[str] = Field(default=None, max_length=500)
  action: FirewallRuleAction
  source_ip: Optional[str] = Field(default=None, max_length=45)
  destination_ip: Optional[str] = Field(default=None, max_length=45)
  source_port: Optional[int] = Field(default=None, ge=1, le=65535)
  destination_port: Optional[int] = Field(default=None, ge=1, le=65535)
  protocol: FirewallProtocol = FirewallProtocol.ANY
  priority: int = Field(default=100, ge=1, le=1000)
  is_enabled: bool = True
  expires_at: Optional[datetime] = None
  source_country: Optional[str] = Field(default=None, min_length=2, max_length=2)
  destination_country: Optional[str] = Field(default=None, min_length=2, max_length=2)
  is_automatic: bool = False
  trigger_source: Optional[str] = Field(default=None, max_length=50)
  trigger_reference_id: Optional[str] = Field(default=None, max_length=100)

  @field_validator("name")
  @classmethod
  def validate_name(cls, value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
      raise ValueError("Rule name cannot be empty")
    return cleaned

  @field_validator("source_ip", "destination_ip", mode="before")
  @classmethod
  def normalize_ip_fields(cls, value: Any) -> Optional[str]:
    return normalize_ip_constraint(value)

  @field_validator("source_port", "destination_port", mode="before")
  @classmethod
  def normalize_port_fields(cls, value: Any) -> Optional[int]:
    return normalize_port_constraint(value)

  @field_validator("protocol", mode="before")
  @classmethod
  def normalize_protocol_field(cls, value: Any) -> Any:
    return normalize_protocol_constraint(value)

  @model_validator(mode="after")
  def validate_temporary_block(self):
    if self.action == FirewallRuleAction.TEMPORARY_BLOCK and self.expires_at is None:
      raise ValueError("expires_at is required for temporary_block rules")

    if self.action != FirewallRuleAction.TEMPORARY_BLOCK and self.expires_at is not None:
      raise ValueError("expires_at is only allowed for temporary_block rules")

    if self.expires_at is not None:
      expires_at = self.expires_at
      if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
      if expires_at <= datetime.now(timezone.utc):
        raise ValueError("expires_at must be in the future")

    return self


class FirewallRuleCreate(FirewallRuleBase):
  pass


class FirewallRuleUpdate(BaseModel):
  name: Optional[str] = Field(default=None, min_length=3, max_length=100)
  description: Optional[str] = Field(default=None, max_length=500)
  action: Optional[FirewallRuleAction] = None
  source_ip: Optional[str] = Field(default=None, max_length=45)
  destination_ip: Optional[str] = Field(default=None, max_length=45)
  source_port: Optional[int] = Field(default=None, ge=1, le=65535)
  destination_port: Optional[int] = Field(default=None, ge=1, le=65535)
  protocol: Optional[FirewallProtocol] = None
  priority: Optional[int] = Field(default=None, ge=1, le=1000)
  is_enabled: Optional[bool] = None
  expires_at: Optional[datetime] = None
  source_country: Optional[str] = Field(default=None, min_length=2, max_length=2)
  destination_country: Optional[str] = Field(default=None, min_length=2, max_length=2)
  is_automatic: Optional[bool] = None
  trigger_source: Optional[str] = Field(default=None, max_length=50)
  trigger_reference_id: Optional[str] = Field(default=None, max_length=100)

  @field_validator("source_ip", "destination_ip", mode="before")
  @classmethod
  def normalize_ip_fields(cls, value: Any) -> Optional[str]:
    return normalize_ip_constraint(value)

  @field_validator("source_port", "destination_port", mode="before")
  @classmethod
  def normalize_port_fields(cls, value: Any) -> Optional[int]:
    return normalize_port_constraint(value)

  @field_validator("protocol", mode="before")
  @classmethod
  def normalize_protocol_field(cls, value: Any) -> Any:
    return normalize_protocol_constraint(value)

  @model_validator(mode="after")
  def validate_temporary_block_update(self):
    if self.action == FirewallRuleAction.TEMPORARY_BLOCK and self.expires_at is None:
      raise ValueError("expires_at is required when action is temporary_block")

    if self.expires_at is not None:
      expires_at = self.expires_at
      if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
      if expires_at <= datetime.now(timezone.utc):
        raise ValueError("expires_at must be in the future")

    return self


class FirewallRuleInDB(FirewallRuleBase):
  model_config = ConfigDict(populate_by_name=True)

  id: PyObjectId = Field(alias="_id")
  rule_id: str
  created_by: Optional[str] = None
  created_at: datetime
  updated_at: datetime
  is_expired: bool = False


class FirewallRulePublic(BaseModel):
  model_config = ConfigDict(populate_by_name=True)

  id: PyObjectId = Field(alias="_id")
  rule_id: str
  name: str
  description: Optional[str] = None
  action: FirewallRuleAction
  source_ip: Optional[str] = None
  destination_ip: Optional[str] = None
  source_port: Optional[int] = None
  destination_port: Optional[int] = None
  protocol: FirewallProtocol
  priority: int
  is_enabled: bool
  expires_at: Optional[datetime] = None
  is_expired: bool = False
  source_country: Optional[str] = None
  destination_country: Optional[str] = None
  is_automatic: bool = False
  trigger_source: Optional[str] = None
  trigger_reference_id: Optional[str] = None
  created_by: Optional[str] = None
  created_at: datetime
  updated_at: datetime


class FirewallRuleDocument:
  @staticmethod
  def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

  @staticmethod
  def _is_expired(expires_at: Optional[datetime]) -> bool:
    if expires_at is None:
      return False

    if expires_at.tzinfo is None:
      expires_at = expires_at.replace(tzinfo=timezone.utc)

    return expires_at <= FirewallRuleDocument._utc_now()

  @staticmethod
  def create_document(
    rule_data: FirewallRuleCreate,
    created_by: Optional[str] = None,
  ) -> dict[str, Any]:
    now = FirewallRuleDocument._utc_now()

    return {
      "rule_id": str(uuid4()),
      "name": rule_data.name,
      "description": rule_data.description,
      "action": rule_data.action.value,
      "source_ip": rule_data.source_ip,
      "destination_ip": rule_data.destination_ip,
      "source_port": rule_data.source_port,
      "destination_port": rule_data.destination_port,
      "protocol": rule_data.protocol.value,
      "priority": rule_data.priority,
      "is_enabled": rule_data.is_enabled,
      "expires_at": rule_data.expires_at,
      "is_expired": FirewallRuleDocument._is_expired(rule_data.expires_at),
      "source_country": rule_data.source_country.upper() if rule_data.source_country else None,
      "destination_country": rule_data.destination_country.upper() if rule_data.destination_country else None,
      "is_automatic": rule_data.is_automatic,
      "trigger_source": rule_data.trigger_source,
      "trigger_reference_id": rule_data.trigger_reference_id,
      "created_by": created_by,
      "created_at": now,
      "updated_at": now,
    }

  @staticmethod
  def update_document(
    existing_rule: dict[str, Any],
    update_data: FirewallRuleUpdate,
  ) -> dict[str, Any]:
    update_fields = update_data.model_dump(exclude_unset=True)

    if update_data.action is not None:
      update_fields["action"] = update_data.action.value

    if update_data.protocol is not None:
      update_fields["protocol"] = update_data.protocol.value

    merged_rule = {**existing_rule, **update_fields}
    expires_at = merged_rule.get("expires_at")
    update_fields["is_expired"] = FirewallRuleDocument._is_expired(expires_at)
    update_fields["updated_at"] = FirewallRuleDocument._utc_now()

    return {**existing_rule, **update_fields}

  @staticmethod
  def from_mongo(document: Optional[dict[str, Any]]) -> Optional[FirewallRuleInDB]:
    if document is None:
      return None

    document_copy = dict(document)
    document_copy["_id"] = str(document_copy["_id"])

    expires_at = document_copy.get("expires_at")
    document_copy["is_expired"] = FirewallRuleDocument._is_expired(expires_at)

    return FirewallRuleInDB(**document_copy)

  @staticmethod
  def to_public(rule: FirewallRuleInDB) -> FirewallRulePublic:
    return FirewallRulePublic(
      _id=rule.id,
      rule_id=rule.rule_id,
      name=rule.name,
      description=rule.description,
      action=rule.action,
      source_ip=rule.source_ip,
      destination_ip=rule.destination_ip,
      source_port=rule.source_port,
      destination_port=rule.destination_port,
      protocol=rule.protocol,
      priority=rule.priority,
      is_enabled=rule.is_enabled,
      expires_at=rule.expires_at,
      is_expired=rule.is_expired,
      source_country=rule.source_country,
      destination_country=rule.destination_country,
      is_automatic=rule.is_automatic,
      trigger_source=rule.trigger_source,
      trigger_reference_id=rule.trigger_reference_id,
      created_by=rule.created_by,
      created_at=rule.created_at,
      updated_at=rule.updated_at,
    )

  @staticmethod
  def to_public_from_mongo(document: Optional[dict[str, Any]]) -> Optional[FirewallRulePublic]:
    rule = FirewallRuleDocument.from_mongo(document)
    if rule is None:
      return None
    return FirewallRuleDocument.to_public(rule)
