from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class IncidentStatus(str, Enum):
  OPEN = "open"
  INVESTIGATING = "investigating"
  CONTAINED = "contained"
  RESOLVED = "resolved"
  CLOSED = "closed"


class IncidentSeverity(str, Enum):
  INFO = "info"
  WARNING = "warning"
  ERROR = "error"
  CRITICAL = "critical"


class IncidentActionType(str, Enum):
  BLOCK_IP = "block_ip"
  KILL_SESSION = "kill_session"
  GENERATE_REPORT = "generate_report"
  STATUS_CHANGE = "status_change"
  NOTE = "note"


def utc_now() -> datetime:
  return datetime.now(timezone.utc)


class IncidentActionRecord(BaseModel):
  action_id: str
  action_type: IncidentActionType
  actor_id: str
  actor_username: str
  timestamp: datetime
  details: dict[str, Any] = Field(default_factory=dict)


class IncidentCreate(BaseModel):
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


class IncidentUpdate(BaseModel):
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


class IncidentPublic(BaseModel):
  incident_id: str
  title: str
  description: str
  severity: IncidentSeverity
  status: IncidentStatus
  threat_type: Optional[str] = None
  source_ip: Optional[str] = None
  destination_ip: Optional[str] = None
  affected_user_id: Optional[str] = None
  affected_device_id: Optional[str] = None
  assigned_to: Optional[str] = None
  trigger_source: str
  trigger_reference_id: Optional[str] = None
  actions_taken: list[IncidentActionRecord] = Field(default_factory=list)
  firewall_rule_ids: list[str] = Field(default_factory=list)
  session_ids_killed: list[str] = Field(default_factory=list)
  report_ids: list[str] = Field(default_factory=list)
  metadata: dict[str, Any] = Field(default_factory=dict)
  detected_at: datetime
  resolved_at: Optional[datetime] = None
  created_by: str
  created_at: datetime
  updated_at: datetime


class IncidentDocument:
  @staticmethod
  def create_document(
    incident_data: IncidentCreate,
    created_by: str,
  ) -> dict[str, Any]:
    now = utc_now()

    return {
      "incident_id": str(uuid4()),
      "title": incident_data.title,
      "description": incident_data.description,
      "severity": incident_data.severity.value,
      "status": IncidentStatus.OPEN.value,
      "threat_type": incident_data.threat_type,
      "source_ip": incident_data.source_ip,
      "destination_ip": incident_data.destination_ip,
      "affected_user_id": incident_data.affected_user_id,
      "affected_device_id": incident_data.affected_device_id,
      "assigned_to": incident_data.assigned_to,
      "trigger_source": incident_data.trigger_source,
      "trigger_reference_id": incident_data.trigger_reference_id,
      "actions_taken": [],
      "firewall_rule_ids": [],
      "session_ids_killed": [],
      "report_ids": [],
      "metadata": incident_data.metadata,
      "detected_at": now,
      "resolved_at": None,
      "created_by": created_by,
      "created_at": now,
      "updated_at": now,
    }

  @staticmethod
  def to_public(document: dict[str, Any]) -> IncidentPublic:
    actions = [
      IncidentActionRecord(**action) if isinstance(action, dict) else action
      for action in document.get("actions_taken", [])
    ]

    return IncidentPublic(
      incident_id=document["incident_id"],
      title=document["title"],
      description=document["description"],
      severity=IncidentSeverity(document["severity"]),
      status=IncidentStatus(document["status"]),
      threat_type=document.get("threat_type"),
      source_ip=document.get("source_ip"),
      destination_ip=document.get("destination_ip"),
      affected_user_id=document.get("affected_user_id"),
      affected_device_id=document.get("affected_device_id"),
      assigned_to=document.get("assigned_to"),
      trigger_source=document["trigger_source"],
      trigger_reference_id=document.get("trigger_reference_id"),
      actions_taken=actions,
      firewall_rule_ids=document.get("firewall_rule_ids", []),
      session_ids_killed=document.get("session_ids_killed", []),
      report_ids=document.get("report_ids", []),
      metadata=document.get("metadata", {}),
      detected_at=document["detected_at"],
      resolved_at=document.get("resolved_at"),
      created_by=document["created_by"],
      created_at=document["created_at"],
      updated_at=document["updated_at"],
    )

  @staticmethod
  def create_action_record(
    action_type: IncidentActionType,
    actor_id: str,
    actor_username: str,
    details: Optional[dict[str, Any]] = None,
  ) -> dict[str, Any]:
    return {
      "action_id": str(uuid4()),
      "action_type": action_type.value,
      "actor_id": actor_id,
      "actor_username": actor_username,
      "timestamp": utc_now(),
      "details": details or {},
    }


class SessionDocument:
  @staticmethod
  def create_document(
    user_id: str,
    username: str,
    access_jti: str,
    refresh_jti: str,
    expires_at: datetime,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
  ) -> dict[str, Any]:
    now = utc_now()

    return {
      "session_id": str(uuid4()),
      "user_id": user_id,
      "username": username,
      "ip_address": ip_address,
      "user_agent": user_agent,
      "access_jti": access_jti,
      "refresh_jti": refresh_jti,
      "is_active": True,
      "created_at": now,
      "expires_at": expires_at,
      "revoked_at": None,
      "revoked_by": None,
      "revoked_reason": None,
    }
