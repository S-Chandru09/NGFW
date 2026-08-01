from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional
from uuid import uuid4

from bson import ObjectId
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field


class TrustLevel(str, Enum):
  CRITICAL = "critical"
  LOW = "low"
  MEDIUM = "medium"
  HIGH = "high"
  VERIFIED = "verified"


class BehaviourEventType(str, Enum):
  LOGIN_SUCCESS = "login_success"
  LOGIN_FAILURE = "login_failure"
  LOGOUT = "logout"
  UNUSUAL_LOCATION = "unusual_location"
  OFF_HOURS_ACCESS = "off_hours_access"
  PRIVILEGE_ESCALATION = "privilege_escalation"
  DATA_EXFILTRATION = "data_exfiltration"
  POLICY_VIOLATION = "policy_violation"
  MALWARE_DETECTED = "malware_detected"
  NORMAL_ACTIVITY = "normal_activity"


class BehaviourRiskLevel(str, Enum):
  LOW = "low"
  MEDIUM = "medium"
  HIGH = "high"
  CRITICAL = "critical"


def validate_object_id(value: Any) -> str:
  if isinstance(value, ObjectId):
    return str(value)

  if isinstance(value, str) and ObjectId.is_valid(value):
    return value

  raise ValueError("Invalid ObjectId")


PyObjectId = Annotated[str, BeforeValidator(validate_object_id)]


class ScoreFactor(BaseModel):
  factor: str
  impact: float
  description: str


class TrustScoreBreakdown(BaseModel):
  device_score: float = Field(ge=0.0, le=100.0)
  user_score: float = Field(ge=0.0, le=100.0)
  behaviour_score: float = Field(ge=0.0, le=100.0)
  composite_score: float = Field(ge=0.0, le=100.0)
  trust_level: TrustLevel
  is_access_allowed: bool
  min_required_score: float
  device_factors: list[ScoreFactor] = Field(default_factory=list)
  user_factors: list[ScoreFactor] = Field(default_factory=list)
  behaviour_factors: list[ScoreFactor] = Field(default_factory=list)


class BehaviourEventCreate(BaseModel):
  user_id: str
  device_id: Optional[str] = None
  event_type: BehaviourEventType
  risk_level: BehaviourRiskLevel = BehaviourRiskLevel.LOW
  description: str = Field(..., min_length=1, max_length=500)
  ip_address: Optional[str] = Field(default=None, max_length=45)
  metadata: dict[str, Any] = Field(default_factory=dict)


class BehaviourEventPublic(BaseModel):
  model_config = ConfigDict(populate_by_name=True)

  id: PyObjectId = Field(alias="_id")
  event_id: str
  user_id: str
  device_id: Optional[str] = None
  event_type: BehaviourEventType
  risk_level: BehaviourRiskLevel
  description: str
  ip_address: Optional[str] = None
  metadata: dict[str, Any]
  created_at: datetime


class TrustScorePublic(BaseModel):
  model_config = ConfigDict(populate_by_name=True)

  id: PyObjectId = Field(alias="_id")
  score_id: str
  user_id: str
  device_id: Optional[str] = None
  username: Optional[str] = None
  device_name: Optional[str] = None
  device_score: float
  user_score: float
  behaviour_score: float
  composite_score: float
  trust_level: TrustLevel
  is_access_allowed: bool
  breakdown: TrustScoreBreakdown
  metadata: dict[str, Any] = Field(default_factory=dict)
  calculated_at: datetime
  created_at: datetime
  updated_at: datetime


class TrustScoreDocument:
  @staticmethod
  def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

  @staticmethod
  def create_behaviour_event_document(event_data: BehaviourEventCreate) -> dict[str, Any]:
    now = TrustScoreDocument._utc_now()

    return {
      "event_id": str(uuid4()),
      "user_id": event_data.user_id,
      "device_id": event_data.device_id,
      "event_type": event_data.event_type.value,
      "risk_level": event_data.risk_level.value,
      "description": event_data.description.strip(),
      "ip_address": event_data.ip_address,
      "metadata": event_data.metadata,
      "created_at": now,
    }

  @staticmethod
  def create_score_document(
    user_id: str,
    breakdown: TrustScoreBreakdown,
    device_id: Optional[str] = None,
    username: Optional[str] = None,
    device_name: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
    score_id: Optional[str] = None,
    created_at: Optional[datetime] = None,
  ) -> dict[str, Any]:
    now = TrustScoreDocument._utc_now()

    return {
      "score_id": score_id or str(uuid4()),
      "user_id": user_id,
      "device_id": device_id,
      "username": username,
      "device_name": device_name,
      "device_score": breakdown.device_score,
      "user_score": breakdown.user_score,
      "behaviour_score": breakdown.behaviour_score,
      "composite_score": breakdown.composite_score,
      "trust_level": breakdown.trust_level.value,
      "is_access_allowed": breakdown.is_access_allowed,
      "breakdown": breakdown.model_dump(),
      "metadata": metadata or {},
      "calculated_at": now,
      "created_at": created_at or now,
      "updated_at": now,
    }

  @staticmethod
  def from_mongo(document: Optional[dict[str, Any]]) -> Optional[TrustScorePublic]:
    if document is None:
      return None

    document_copy = dict(document)
    document_copy["_id"] = str(document_copy["_id"])
    document_copy["trust_level"] = TrustLevel(document_copy["trust_level"])
    document_copy["breakdown"]["trust_level"] = TrustLevel(document_copy["breakdown"]["trust_level"])
    return TrustScorePublic(**document_copy)

  @staticmethod
  def behaviour_from_mongo(document: Optional[dict[str, Any]]) -> Optional[BehaviourEventPublic]:
    if document is None:
      return None

    document_copy = dict(document)
    document_copy["_id"] = str(document_copy["_id"])
    document_copy["event_type"] = BehaviourEventType(document_copy["event_type"])
    document_copy["risk_level"] = BehaviourRiskLevel(document_copy["risk_level"])
    return BehaviourEventPublic(**document_copy)
