from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional
from uuid import uuid4

from bson import ObjectId
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator


class LogSeverity(str, Enum):
  INFO = "info"
  WARNING = "warning"
  ERROR = "error"
  CRITICAL = "critical"


class LogEventType(str, Enum):
  AUTH = "auth"
  FIREWALL = "firewall"
  THREAT = "threat"
  POLICY = "policy"
  NETWORK = "network"
  SYSTEM = "system"
  ML = "ml"
  DEVICE = "device"
  ACCESS = "access"


def validate_object_id(value: Any) -> str:
  if isinstance(value, ObjectId):
    return str(value)

  if isinstance(value, str) and ObjectId.is_valid(value):
    return value

  raise ValueError("Invalid ObjectId")


PyObjectId = Annotated[str, BeforeValidator(validate_object_id)]


class LogBase(BaseModel):
  event_type: LogEventType
  severity: LogSeverity = LogSeverity.INFO
  message: str = Field(..., min_length=1, max_length=500)
  description: Optional[str] = Field(default=None, max_length=2000)
  user_id: Optional[str] = None
  username: Optional[str] = Field(default=None, max_length=100)
  ip_address: Optional[str] = Field(default=None, max_length=45)
  source: str = Field(..., min_length=1, max_length=100)
  resource_type: Optional[str] = Field(default=None, max_length=100)
  resource_id: Optional[str] = Field(default=None, max_length=100)
  metadata: dict[str, Any] = Field(default_factory=dict)

  @field_validator("ip_address")
  @classmethod
  def validate_ip_address(cls, value: Optional[str]) -> Optional[str]:
    if value is None:
      return value
    return value.strip()


class LogCreate(LogBase):
  pass


class LogInDB(LogBase):
  model_config = ConfigDict(populate_by_name=True)

  id: PyObjectId = Field(alias="_id")
  log_id: str
  created_at: datetime


class LogPublic(BaseModel):
  model_config = ConfigDict(populate_by_name=True)

  id: PyObjectId = Field(alias="_id")
  log_id: str
  event_type: LogEventType
  severity: LogSeverity
  message: str
  description: Optional[str] = None
  user_id: Optional[str] = None
  username: Optional[str] = None
  ip_address: Optional[str] = None
  source: str
  resource_type: Optional[str] = None
  resource_id: Optional[str] = None
  metadata: dict[str, Any] = Field(default_factory=dict)
  created_at: datetime


class LogDocument:
  @staticmethod
  def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

  @staticmethod
  def create_document(log_data: LogCreate) -> dict[str, Any]:
    return {
      "log_id": str(uuid4()),
      "event_type": log_data.event_type.value,
      "severity": log_data.severity.value,
      "message": log_data.message.strip(),
      "description": log_data.description.strip() if log_data.description else None,
      "user_id": log_data.user_id,
      "username": log_data.username,
      "ip_address": log_data.ip_address,
      "source": log_data.source.strip(),
      "resource_type": log_data.resource_type,
      "resource_id": log_data.resource_id,
      "metadata": log_data.metadata,
      "created_at": LogDocument._utc_now(),
    }

  @staticmethod
  def from_mongo(document: Optional[dict[str, Any]]) -> Optional[LogInDB]:
    if document is None:
      return None

    document_copy = dict(document)
    document_copy["_id"] = str(document_copy["_id"])
    return LogInDB(**document_copy)

  @staticmethod
  def to_public(log: LogInDB) -> LogPublic:
    return LogPublic(
      _id=log.id,
      log_id=log.log_id,
      event_type=log.event_type,
      severity=log.severity,
      message=log.message,
      description=log.description,
      user_id=log.user_id,
      username=log.username,
      ip_address=log.ip_address,
      source=log.source,
      resource_type=log.resource_type,
      resource_id=log.resource_id,
      metadata=log.metadata,
      created_at=log.created_at,
    )

  @staticmethod
  def to_public_from_mongo(document: Optional[dict[str, Any]]) -> Optional[LogPublic]:
    log = LogDocument.from_mongo(document)
    if log is None:
      return None
    return LogDocument.to_public(log)
