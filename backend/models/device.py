from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_address
from typing import Annotated, Any, Optional
from uuid import uuid4

from bson import ObjectId
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator


class DeviceType(str, Enum):
  LAPTOP = "laptop"
  DESKTOP = "desktop"
  MOBILE = "mobile"
  TABLET = "tablet"
  SERVER = "server"
  IOT = "iot"
  UNKNOWN = "unknown"


def validate_object_id(value: Any) -> str:
  if isinstance(value, ObjectId):
    return str(value)

  if isinstance(value, str) and ObjectId.is_valid(value):
    return value

  raise ValueError("Invalid ObjectId")


PyObjectId = Annotated[str, BeforeValidator(validate_object_id)]


def normalize_optional_ip(value: Any) -> Optional[str]:
  if value is None:
    return None

  if isinstance(value, str):
    cleaned = value.strip()
    if not cleaned:
      return None

    try:
      return str(ip_address(cleaned))
    except ValueError as exc:
      raise ValueError("ip_address must be a valid IPv4 or IPv6 address") from exc

  raise ValueError("ip_address must be a valid IPv4 or IPv6 address")


class DeviceCreate(BaseModel):
  model_config = ConfigDict(extra="ignore")

  device_name: str = Field(..., min_length=2, max_length=100)
  device_type: DeviceType = DeviceType.UNKNOWN
  os_type: Optional[str] = Field(default=None, max_length=50)
  ip_address: Optional[str] = Field(default=None, max_length=45)
  user_id: Optional[str] = None
  is_compliant: bool = True
  metadata: dict[str, Any] = Field(default_factory=dict)

  @field_validator("device_name")
  @classmethod
  def validate_device_name(cls, value: str) -> str:
    cleaned = value.strip()
    if len(cleaned) < 2:
      raise ValueError("Device name must be at least 2 characters")
    return cleaned

  @field_validator("ip_address", mode="before")
  @classmethod
  def validate_ip_address(cls, value: Any) -> Optional[str]:
    return normalize_optional_ip(value)

  @field_validator("user_id", mode="before")
  @classmethod
  def normalize_user_id(cls, value: Any) -> Optional[str]:
    if value is None:
      return None
    if isinstance(value, str):
      cleaned = value.strip()
      return cleaned or None
    return str(value)


class DeviceUpdate(BaseModel):
  model_config = ConfigDict(extra="ignore")

  device_name: Optional[str] = Field(default=None, min_length=2, max_length=100)
  device_type: Optional[DeviceType] = None
  os_type: Optional[str] = Field(default=None, max_length=50)
  ip_address: Optional[str] = Field(default=None, max_length=45)
  user_id: Optional[str] = None
  is_compliant: Optional[bool] = None
  metadata: Optional[dict[str, Any]] = None

  @field_validator("device_name")
  @classmethod
  def validate_device_name(cls, value: Optional[str]) -> Optional[str]:
    if value is None:
      return value
    cleaned = value.strip()
    if len(cleaned) < 2:
      raise ValueError("Device name must be at least 2 characters")
    return cleaned

  @field_validator("ip_address", mode="before")
  @classmethod
  def validate_ip_address(cls, value: Any) -> Optional[str]:
    return normalize_optional_ip(value)

  @field_validator("user_id", mode="before")
  @classmethod
  def normalize_user_id(cls, value: Any) -> Optional[str]:
    if value is None:
      return None
    if isinstance(value, str):
      cleaned = value.strip()
      return cleaned or None
    return str(value)


class DeviceInDB(BaseModel):
  model_config = ConfigDict(populate_by_name=True)

  id: PyObjectId = Field(alias="_id")
  device_id: str
  device_name: str
  device_type: DeviceType
  os_type: Optional[str] = None
  ip_address: Optional[str] = None
  user_id: Optional[str] = None
  is_trusted: bool = False
  trust_score: float = Field(default=50.0, ge=0.0, le=100.0)
  is_compliant: bool = True
  metadata: dict[str, Any] = Field(default_factory=dict)
  last_seen_at: Optional[datetime] = None
  created_at: datetime
  updated_at: datetime


class DevicePublic(BaseModel):
  model_config = ConfigDict(populate_by_name=True)

  id: PyObjectId = Field(alias="_id")
  device_id: str
  device_name: str
  device_type: DeviceType
  os_type: Optional[str] = None
  ip_address: Optional[str] = None
  user_id: Optional[str] = None
  is_trusted: bool
  trust_score: float
  is_compliant: bool
  last_seen_at: Optional[datetime] = None
  created_at: datetime
  updated_at: datetime


class DeviceDocument:
  @staticmethod
  def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

  @staticmethod
  def create_document(device_data: DeviceCreate) -> dict[str, Any]:
    now = DeviceDocument._utc_now()

    return {
      "device_id": str(uuid4()),
      "device_name": device_data.device_name.strip(),
      "device_type": device_data.device_type.value,
      "os_type": device_data.os_type,
      "ip_address": device_data.ip_address,
      "user_id": device_data.user_id,
      "is_trusted": False,
      "trust_score": 50.0,
      "is_compliant": device_data.is_compliant,
      "metadata": device_data.metadata,
      "last_seen_at": None,
      "created_at": now,
      "updated_at": now,
    }

  @staticmethod
  def update_fields(update_data: DeviceUpdate) -> dict[str, Any]:
    fields = update_data.model_dump(exclude_unset=True)
    fields.pop("trust_score", None)
    fields.pop("is_trusted", None)
    if "device_type" in fields and fields["device_type"] is not None:
      fields["device_type"] = (
        fields["device_type"].value if hasattr(fields["device_type"], "value") else fields["device_type"]
      )
    fields["updated_at"] = DeviceDocument._utc_now()
    return fields

  @staticmethod
  def from_mongo(document: Optional[dict[str, Any]]) -> Optional[DeviceInDB]:
    if document is None:
      return None

    document_copy = dict(document)
    document_copy["_id"] = str(document_copy["_id"])
    return DeviceInDB(**document_copy)

  @staticmethod
  def to_public_from_mongo(document: Optional[dict[str, Any]]) -> Optional[DevicePublic]:
    device = DeviceDocument.from_mongo(document)
    if device is None:
      return None

    return DevicePublic(
      _id=device.id,
      device_id=device.device_id,
      device_name=device.device_name,
      device_type=device.device_type,
      os_type=device.os_type,
      ip_address=device.ip_address,
      user_id=device.user_id,
      is_trusted=device.is_trusted,
      trust_score=device.trust_score,
      is_compliant=device.is_compliant,
      last_seen_at=device.last_seen_at,
      created_at=device.created_at,
      updated_at=device.updated_at,
    )
