import math
import re
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from fastapi import HTTPException, status
from pymongo import ASCENDING, DESCENDING

from database import (
  get_audit_logs_collection,
  get_firewall_rules_collection,
  get_incident_reports_collection,
  get_incidents_collection,
  get_ioc_indicators_collection,
  get_sessions_collection,
)
from models.firewall_engine import AutomaticRuleAction, AutomaticRuleTrigger
from models.incident_response import (
  IncidentActionType,
  IncidentCreate,
  IncidentDocument,
  IncidentSeverity,
  IncidentStatus,
  IncidentUpdate,
  utc_now,
)
from models.log import LogCreate, LogEventType, LogSeverity
from schemas.firewall_engine import AutomaticRuleRequest
from schemas.incident_response import (
  BlockIPRequest,
  BlockIPResponse,
  GenerateReportRequest,
  GenerateReportResponse,
  IncidentCreateResponse,
  IncidentDetailResponse,
  IncidentListResponse,
  IncidentReportContent,
  IncidentReportPublic,
  IncidentReportSection,
  IncidentStatsResponse,
  IncidentUpdateResponse,
  KillSessionRequest,
  KillSessionResponse,
)
from schemas.log import PaginationMeta
from services.firewall_engine import firewall_engine
from services.log_service import log_service
from services.session_service import session_service


class IncidentResponseService:
  def _build_pagination_meta(self, page: int, page_size: int, total_items: int) -> PaginationMeta:
    total_pages = math.ceil(total_items / page_size) if page_size > 0 else 0

    return PaginationMeta(
      page=page,
      page_size=page_size,
      total_items=total_items,
      total_pages=total_pages,
      has_next=page < total_pages,
      has_previous=page > 1 and total_pages > 0,
    )

  async def _get_incident_document(self, incident_id: str) -> dict[str, Any]:
    incidents = get_incidents_collection()
    document = await incidents.find_one({"incident_id": incident_id})

    if document is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Incident '{incident_id}' not found",
      )

    return document

  async def _append_action(
    self,
    incident_id: str,
    action_type: IncidentActionType,
    actor_id: str,
    actor_username: str,
    details: Optional[dict[str, Any]] = None,
    extra_updates: Optional[dict[str, Any]] = None,
  ) -> dict[str, Any]:
    incidents = get_incidents_collection()
    action_record = IncidentDocument.create_action_record(
      action_type=action_type,
      actor_id=actor_id,
      actor_username=actor_username,
      details=details,
    )

    update_fields: dict[str, Any] = {
      "updated_at": utc_now(),
    }

    if extra_updates:
      update_fields.update(extra_updates)

    await incidents.update_one(
      {"incident_id": incident_id},
      {
        "$push": {"actions_taken": action_record},
        "$set": update_fields,
      },
    )

    return await self._get_incident_document(incident_id)

  async def _create_audit_log(
    self,
    message: str,
    severity: LogSeverity,
    actor_id: str,
    actor_username: str,
    incident_id: str,
    ip_address: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
  ) -> None:
    await log_service.create_log(
      LogCreate(
        event_type=LogEventType.THREAT,
        severity=severity,
        message=message,
        description=f"Incident response action for incident {incident_id}",
        user_id=actor_id,
        username=actor_username,
        ip_address=ip_address,
        source="incident_response",
        resource_type="incident",
        resource_id=incident_id,
        metadata=metadata or {},
      )
    )

  async def create_incident(
    self,
    incident_data: IncidentCreate,
    created_by: str,
    actor_username: str,
  ) -> IncidentCreateResponse:
    incidents = get_incidents_collection()
    document = IncidentDocument.create_document(incident_data, created_by=created_by)

    await incidents.insert_one(document)

    await self._create_audit_log(
      message=f"Incident created: {document['title']}",
      severity=LogSeverity(document["severity"]),
      actor_id=created_by,
      actor_username=actor_username,
      incident_id=document["incident_id"],
      ip_address=document.get("source_ip"),
      metadata={"status": document["status"], "threat_type": document.get("threat_type")},
    )

    return IncidentCreateResponse(
      success=True,
      message="Incident created successfully",
      incident=IncidentDocument.to_public(document),
    )

  async def get_incident(self, incident_id: str) -> IncidentDetailResponse:
    document = await self._get_incident_document(incident_id)

    return IncidentDetailResponse(
      success=True,
      message="Incident retrieved successfully",
      incident=IncidentDocument.to_public(document),
    )

  async def list_incidents(
    self,
    page: int = 1,
    page_size: int = 20,
    status_filter: Optional[IncidentStatus] = None,
    severity_filter: Optional[IncidentSeverity] = None,
    search: Optional[str] = None,
  ) -> IncidentListResponse:
    incidents = get_incidents_collection()
    query: dict[str, Any] = {}

    if status_filter:
      query["status"] = status_filter.value

    if severity_filter:
      query["severity"] = severity_filter.value

    if search:
      search_regex = {"$regex": re.escape(search.strip()), "$options": "i"}
      query["$or"] = [
        {"title": search_regex},
        {"description": search_regex},
        {"source_ip": search_regex},
        {"threat_type": search_regex},
        {"incident_id": search_regex},
      ]

    total_items = await incidents.count_documents(query)
    skip = (page - 1) * page_size

    cursor = (
      incidents.find(query)
      .sort("created_at", DESCENDING)
      .skip(skip)
      .limit(page_size)
    )

    items = [IncidentDocument.to_public(document) async for document in cursor]

    return IncidentListResponse(
      success=True,
      message="Incidents retrieved successfully",
      items=items,
      pagination=self._build_pagination_meta(page, page_size, total_items),
    )

  async def update_incident(
    self,
    incident_id: str,
    update_data: IncidentUpdate,
    actor_id: str,
    actor_username: str,
  ) -> IncidentUpdateResponse:
    document = await self._get_incident_document(incident_id)
    updates = update_data.model_dump(exclude_none=True)

    if not updates:
      return IncidentUpdateResponse(
        success=True,
        message="No changes provided",
        incident=IncidentDocument.to_public(document),
      )

    previous_status = document.get("status")
    updates["updated_at"] = utc_now()

    if "status" in updates:
      updates["status"] = updates["status"].value if hasattr(updates["status"], "value") else updates["status"]

      if updates["status"] in (IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value):
        updates["resolved_at"] = utc_now()

    if "severity" in updates and hasattr(updates["severity"], "value"):
      updates["severity"] = updates["severity"].value

    incidents = get_incidents_collection()
    await incidents.update_one({"incident_id": incident_id}, {"$set": updates})

    if "status" in updates and updates["status"] != previous_status:
      await self._append_action(
        incident_id=incident_id,
        action_type=IncidentActionType.STATUS_CHANGE,
        actor_id=actor_id,
        actor_username=actor_username,
        details={
          "previous_status": previous_status,
          "new_status": updates["status"],
        },
      )

    updated_document = await self._get_incident_document(incident_id)

    return IncidentUpdateResponse(
      success=True,
      message="Incident updated successfully",
      incident=IncidentDocument.to_public(updated_document),
    )

  async def block_ip(
    self,
    incident_id: str,
    request: BlockIPRequest,
    actor_id: str,
    actor_username: str,
  ) -> BlockIPResponse:
    document = await self._get_incident_document(incident_id)
    blocked_ip = request.ip_address or document.get("source_ip")

    if not blocked_ip:
      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="IP address is required. Provide ip_address or set source_ip on the incident.",
      )

    rule_response = await firewall_engine.create_automatic_rule(
      AutomaticRuleRequest(
        trigger=AutomaticRuleTrigger.THREAT_DETECTED,
        source_ip=blocked_ip,
        destination_ip=document.get("destination_ip"),
        threat_type=document.get("threat_type") or "incident_response",
        reference_id=incident_id,
        action=request.action,
        duration_hours=request.duration_hours,
        priority=request.priority,
      ),
      created_by=actor_id,
    )

    firewall_rule_id = rule_response.rule.rule_id
    incidents = get_incidents_collection()

    await incidents.update_one(
      {"incident_id": incident_id},
      {
        "$addToSet": {"firewall_rule_ids": firewall_rule_id},
        "$set": {
          "status": IncidentStatus.CONTAINED.value
          if document.get("status") in (IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value)
          else document.get("status"),
          "updated_at": utc_now(),
        },
        "$push": {
          "actions_taken": IncidentDocument.create_action_record(
            action_type=IncidentActionType.BLOCK_IP,
            actor_id=actor_id,
            actor_username=actor_username,
            details={
              "blocked_ip": blocked_ip,
              "firewall_rule_id": firewall_rule_id,
              "firewall_rule_name": rule_response.rule.name,
              "action": request.action.value,
              "duration_hours": request.duration_hours,
              "reason": request.reason,
            },
          ),
        },
      },
    )

    await self._create_audit_log(
      message=f"Blocked IP {blocked_ip} for incident {incident_id}",
      severity=LogSeverity.WARNING,
      actor_id=actor_id,
      actor_username=actor_username,
      incident_id=incident_id,
      ip_address=blocked_ip,
      metadata={
        "action": "block_ip",
        "firewall_rule_id": firewall_rule_id,
        "reason": request.reason,
      },
    )

    updated_document = await self._get_incident_document(incident_id)

    return BlockIPResponse(
      success=True,
      message=f"IP {blocked_ip} blocked successfully",
      incident=IncidentDocument.to_public(updated_document),
      blocked_ip=blocked_ip,
      firewall_rule_id=firewall_rule_id,
      firewall_rule_name=rule_response.rule.name,
    )

  async def kill_session(
    self,
    incident_id: str,
    request: KillSessionRequest,
    actor_id: str,
    actor_username: str,
  ) -> KillSessionResponse:
    document = await self._get_incident_document(incident_id)

    target_user_id = request.user_id or document.get("affected_user_id")
    target_ip = request.ip_address or document.get("source_ip")

    if not any([request.session_id, target_user_id, target_ip]):
      raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Provide session_id, user_id, ip_address, or set affected_user_id/source_ip on the incident.",
      )

    reason = request.reason or f"Incident response kill session for incident {incident_id}"

    session_ids, revoked_count = await session_service.kill_sessions(
      revoked_by=actor_id,
      reason=reason,
      session_id=request.session_id,
      user_id=target_user_id,
      ip_address=target_ip if not request.session_id and not request.kill_all_for_user else request.ip_address,
      kill_all_for_user=request.kill_all_for_user,
    )

    if not session_ids:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="No active sessions found matching the provided criteria",
      )

    incidents = get_incidents_collection()

    await incidents.update_one(
      {"incident_id": incident_id},
      {
        "$addToSet": {"session_ids_killed": {"$each": session_ids}},
        "$set": {
          "status": IncidentStatus.CONTAINED.value
          if document.get("status") in (IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value)
          else document.get("status"),
          "updated_at": utc_now(),
        },
        "$push": {
          "actions_taken": IncidentDocument.create_action_record(
            action_type=IncidentActionType.KILL_SESSION,
            actor_id=actor_id,
            actor_username=actor_username,
            details={
              "session_ids": session_ids,
              "revoked_token_count": revoked_count,
              "user_id": target_user_id,
              "ip_address": target_ip,
              "kill_all_for_user": request.kill_all_for_user,
              "reason": reason,
            },
          ),
        },
      },
    )

    await self._create_audit_log(
      message=f"Killed {len(session_ids)} session(s) for incident {incident_id}",
      severity=LogSeverity.WARNING,
      actor_id=actor_id,
      actor_username=actor_username,
      incident_id=incident_id,
      ip_address=target_ip,
      metadata={
        "action": "kill_session",
        "session_ids": session_ids,
        "revoked_token_count": revoked_count,
      },
    )

    updated_document = await self._get_incident_document(incident_id)

    return KillSessionResponse(
      success=True,
      message=f"Successfully killed {len(session_ids)} session(s)",
      incident=IncidentDocument.to_public(updated_document),
      sessions_killed=len(session_ids),
      session_ids=session_ids,
      revoked_token_count=revoked_count,
    )

  async def _fetch_ioc_enrichment(self, ip_address: Optional[str]) -> dict[str, Any]:
    if not ip_address:
      return {}

    ioc_collection = get_ioc_indicators_collection()
    matches = [
      document
      async for document in ioc_collection.find({
        "ioc_type": "ip",
        "value": ip_address,
        "is_active": True,
      }).limit(5)
    ]

    if not matches:
      return {"ip_address": ip_address, "ioc_matches": []}

    return {
      "ip_address": ip_address,
      "ioc_matches": [
        {
          "ioc_id": match.get("ioc_id"),
          "is_malicious": match.get("is_malicious"),
          "threat_level": match.get("threat_level"),
          "reputation_score": match.get("reputation_score"),
          "source": match.get("source"),
        }
        for match in matches
      ],
    }

  async def generate_report(
    self,
    incident_id: str,
    request: GenerateReportRequest,
    actor_id: str,
    actor_username: str,
  ) -> GenerateReportResponse:
    document = await self._get_incident_document(incident_id)
    incident = IncidentDocument.to_public(document)
    sections: list[IncidentReportSection] = []
    recommendations: list[str] = []

    summary = {
      "incident_id": incident.incident_id,
      "title": incident.title,
      "severity": incident.severity.value,
      "status": incident.status.value,
      "source_ip": incident.source_ip,
      "threat_type": incident.threat_type,
      "actions_count": len(incident.actions_taken),
      "detected_at": incident.detected_at.isoformat(),
      "generated_at": utc_now().isoformat(),
    }

    if request.include_firewall_rules and incident.firewall_rule_ids:
      rules_collection = get_firewall_rules_collection()
      rules = [
        {
          "rule_id": rule.get("rule_id"),
          "name": rule.get("name"),
          "action": rule.get("action"),
          "source_ip": rule.get("source_ip"),
          "priority": rule.get("priority"),
          "is_automatic": rule.get("is_automatic"),
          "trigger_source": rule.get("trigger_source"),
        }
        async for rule in rules_collection.find({"rule_id": {"$in": incident.firewall_rule_ids}})
      ]
      sections.append(IncidentReportSection(title="Firewall Rules", data={"rules": rules}))

      if rules:
        recommendations.append("Review automatic firewall rules created during containment.")

    if request.include_session_history and incident.session_ids_killed:
      session_docs = [
        {
          "session_id": session.get("session_id"),
          "user_id": session.get("user_id"),
          "username": session.get("username"),
          "ip_address": session.get("ip_address"),
          "revoked_at": session.get("revoked_at"),
          "revoked_reason": session.get("revoked_reason"),
        }
        async for session in get_sessions_collection().find({"session_id": {"$in": incident.session_ids_killed}})
      ]
      sections.append(IncidentReportSection(title="Terminated Sessions", data={"sessions": session_docs}))

    if request.include_audit_logs:
      audit_logs = get_audit_logs_collection()
      logs = [
        {
          "log_id": log.get("log_id"),
          "event_type": log.get("event_type"),
          "severity": log.get("severity"),
          "message": log.get("message"),
          "username": log.get("username"),
          "ip_address": log.get("ip_address"),
          "created_at": log.get("created_at"),
        }
        async for log in audit_logs.find({"resource_id": incident_id}).sort("created_at", ASCENDING).limit(50)
      ]
      sections.append(IncidentReportSection(title="Audit Trail", data={"logs": logs}))

    if request.include_ioc_enrichment:
      ioc_data = await self._fetch_ioc_enrichment(incident.source_ip)
      if ioc_data:
        sections.append(IncidentReportSection(title="IOC Enrichment", data=ioc_data))

        if ioc_data.get("ioc_matches"):
          recommendations.append("Correlate incident source IP with matched IOC indicators.")

    sections.append(
      IncidentReportSection(
        title="Response Actions",
        data={
          "actions": [action.model_dump() for action in incident.actions_taken],
        },
      )
    )

    if incident.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING):
      recommendations.append("Continue investigation and apply containment actions if threat is confirmed.")

    if incident.severity in (IncidentSeverity.CRITICAL, IncidentSeverity.ERROR):
      recommendations.append("Escalate to senior analyst and monitor for lateral movement.")

    if request.notes:
      sections.append(IncidentReportSection(title="Analyst Notes", data={"notes": request.notes}))

    report_id = str(uuid4())
    report_content = IncidentReportContent(
      incident=incident,
      summary=summary,
      sections=sections,
      recommendations=recommendations,
    )

    report_document = {
      "report_id": report_id,
      "incident_id": incident_id,
      "title": f"Incident Report: {incident.title}",
      "format": "json",
      "content": report_content.model_dump(mode="json"),
      "generated_by": actor_id,
      "generated_at": utc_now(),
    }

    reports = get_incident_reports_collection()
    await reports.insert_one(report_document)

    incidents = get_incidents_collection()
    await incidents.update_one(
      {"incident_id": incident_id},
      {
        "$addToSet": {"report_ids": report_id},
        "$set": {"updated_at": utc_now()},
        "$push": {
          "actions_taken": IncidentDocument.create_action_record(
            action_type=IncidentActionType.GENERATE_REPORT,
            actor_id=actor_id,
            actor_username=actor_username,
            details={
              "report_id": report_id,
              "sections_count": len(sections),
              "notes": request.notes,
            },
          ),
        },
      },
    )

    await self._create_audit_log(
      message=f"Generated incident report {report_id}",
      severity=LogSeverity.INFO,
      actor_id=actor_id,
      actor_username=actor_username,
      incident_id=incident_id,
      metadata={"action": "generate_report", "report_id": report_id},
    )

    updated_document = await self._get_incident_document(incident_id)
    report_public = IncidentReportPublic(
      report_id=report_id,
      incident_id=incident_id,
      title=report_document["title"],
      format="json",
      content=report_content,
      generated_by=actor_id,
      generated_at=report_document["generated_at"],
    )

    return GenerateReportResponse(
      success=True,
      message="Incident report generated successfully",
      incident=IncidentDocument.to_public(updated_document),
      report=report_public,
    )

  async def get_stats(self) -> IncidentStatsResponse:
    incidents = get_incidents_collection()
    reports = get_incident_reports_collection()

    total_incidents = await incidents.count_documents({})
    open_incidents = await incidents.count_documents({"status": IncidentStatus.OPEN.value})
    investigating_incidents = await incidents.count_documents({"status": IncidentStatus.INVESTIGATING.value})
    contained_incidents = await incidents.count_documents({"status": IncidentStatus.CONTAINED.value})
    resolved_incidents = await incidents.count_documents({
      "status": {"$in": [IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value]},
    })
    critical_incidents = await incidents.count_documents({"severity": IncidentSeverity.CRITICAL.value})
    reports_generated_total = await reports.count_documents({})

    pipeline = [
      {"$unwind": "$actions_taken"},
      {
        "$group": {
          "_id": "$actions_taken.action_type",
          "count": {"$sum": 1},
        }
      },
    ]

    action_counts: dict[str, int] = {}
    async for result in incidents.aggregate(pipeline):
      action_counts[result["_id"]] = result["count"]

    severity_pipeline = [
      {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]
    severity_distribution: dict[str, int] = {}
    async for result in incidents.aggregate(severity_pipeline):
      severity_distribution[result["_id"]] = result["count"]

    status_pipeline = [
      {"$group": {"_id": "$status", "count": {"$sum": 1}}},
    ]
    status_distribution: dict[str, int] = {}
    async for result in incidents.aggregate(status_pipeline):
      status_distribution[result["_id"]] = result["count"]

    blocked_ips_total = action_counts.get(IncidentActionType.BLOCK_IP.value, 0)
    sessions_killed_total = action_counts.get(IncidentActionType.KILL_SESSION.value, 0)
    actions_taken_total = sum(action_counts.values())

    return IncidentStatsResponse(
      success=True,
      message="Incident response statistics retrieved",
      total_incidents=total_incidents,
      open_incidents=open_incidents,
      investigating_incidents=investigating_incidents,
      contained_incidents=contained_incidents,
      resolved_incidents=resolved_incidents,
      critical_incidents=critical_incidents,
      actions_taken_total=actions_taken_total,
      blocked_ips_total=blocked_ips_total,
      sessions_killed_total=sessions_killed_total,
      reports_generated_total=reports_generated_total,
      severity_distribution=severity_distribution,
      status_distribution=status_distribution,
      generated_at=utc_now(),
    )


incident_response_service = IncidentResponseService()
