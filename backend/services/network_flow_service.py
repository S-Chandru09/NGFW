import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from bson import ObjectId
from fastapi import HTTPException, status
from pymongo.errors import DuplicateKeyError

from core.websocket_manager import websocket_manager
from database import (
  get_devices_collection,
  get_network_flows_collection,
  get_packet_uploads_collection,
  get_threat_alerts_collection,
  get_users_collection,
)
from models.firewall_rule import FirewallProtocol
from schemas.firewall_engine import FirewallFlowRequest
from schemas.network_flow import (
  NetworkFlowBatchIngestRequest,
  NetworkFlowBatchIngestResponse,
  NetworkFlowIngestRequest,
  NetworkFlowIngestResponse,
)
from services.firewall_engine import firewall_engine
from services.trust_score_service import trust_score_service

logger = logging.getLogger("ai-ngfw.network_flow")


def _utc_now() -> datetime:
  return datetime.now(timezone.utc)


def _parse_datetime(value: Optional[datetime | str]) -> datetime:
  if value is None:
    return _utc_now()

  if isinstance(value, datetime):
    if value.tzinfo is None:
      return value.replace(tzinfo=timezone.utc)
    return value

  normalized = value.replace("Z", "+00:00")
  try:
    parsed = datetime.fromisoformat(normalized)
  except ValueError as exc:
    raise HTTPException(
      status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
      detail=f"Invalid datetime value: {value}",
    ) from exc

  if parsed.tzinfo is None:
    return parsed.replace(tzinfo=timezone.utc)

  return parsed


def _map_threat_severity(threat_level: Optional[str], confidence: Optional[float]) -> str:
  normalized = (threat_level or "").lower()

  if normalized in {"critical", "high", "medium", "low"}:
    return normalized

  if confidence is not None:
    if confidence >= 0.9:
      return "critical"
    if confidence >= 0.75:
      return "high"
    if confidence >= 0.5:
      return "medium"

  return "low"


def _firewall_port(port: Optional[int]) -> Optional[int]:
  if port is None or port <= 0:
    return None
  return port


def _firewall_protocol(protocol: Optional[str]) -> FirewallProtocol:
  if not protocol:
    return FirewallProtocol.ANY

  normalized = protocol.strip().lower()
  try:
    return FirewallProtocol(normalized)
  except ValueError:
    return FirewallProtocol.ANY


class NetworkFlowService:
  async def _resolve_firewall_action(self, flow_data: NetworkFlowIngestRequest) -> Optional[str]:
    if flow_data.action:
      return flow_data.action

    if not flow_data.source_ip or not flow_data.destination_ip:
      return flow_data.action

    try:
      evaluation = await firewall_engine.evaluate_flow(
        FirewallFlowRequest(
          source_ip=flow_data.source_ip,
          destination_ip=flow_data.destination_ip,
          source_port=_firewall_port(flow_data.source_port),
          destination_port=_firewall_port(flow_data.destination_port),
          protocol=_firewall_protocol(flow_data.protocol),
          flow_id=flow_data.flow_id,
        )
      )
      return evaluation.decision
    except Exception:
      logger.exception(
        "Firewall evaluation failed during flow ingest; persisting flow without a block action | flow_id=%s",
        flow_data.flow_id,
      )
      return flow_data.action

  async def _find_device_by_id(self, device_id: str) -> Optional[dict[str, Any]]:
    devices_collection = get_devices_collection()
    document = await devices_collection.find_one({"device_id": device_id})
    if document is None and ObjectId.is_valid(device_id):
      document = await devices_collection.find_one({"_id": ObjectId(device_id)})
    return document

  async def _find_device_by_source_ip(self, source_ip: Optional[str]) -> Optional[dict[str, Any]]:
    if not source_ip:
      return None

    devices_collection = get_devices_collection()
    return await devices_collection.find_one({"ip_address": source_ip.strip()})

  async def _find_existing_user_id(self, user_id: str) -> Optional[str]:
    users_collection = get_users_collection()
    document = None

    if ObjectId.is_valid(user_id):
      document = await users_collection.find_one({"_id": ObjectId(user_id)})

    if document is None:
      document = await users_collection.find_one({"username": user_id.strip().lower()})

    if document is None:
      return None

    return str(document["_id"])

  async def _resolve_uploaded_by(self, flow_data: NetworkFlowIngestRequest) -> Optional[str]:
    if flow_data.uploaded_by:
      return flow_data.uploaded_by.strip() or None

    upload_id = (flow_data.metadata or {}).get("upload_id")
    if not upload_id:
      return None

    uploads_collection = get_packet_uploads_collection()
    upload_document = await uploads_collection.find_one({"upload_id": upload_id})
    if not upload_document:
      return None

    uploaded_by = upload_document.get("uploaded_by")
    if not uploaded_by:
      return None

    return str(uploaded_by).strip() or None

  async def _resolve_flow_correlation(
    self,
    flow_data: NetworkFlowIngestRequest,
  ) -> tuple[Optional[str], Optional[str], Optional[str]]:
    device_id: Optional[str] = None
    user_id: Optional[str] = None
    uploaded_by: Optional[str] = None

    try:
      uploaded_by = await self._resolve_uploaded_by(flow_data)
    except Exception:
      logger.exception(
        "Uploader attribution lookup failed during flow ingest | flow_id=%s",
        flow_data.flow_id,
      )

    device_document: Optional[dict[str, Any]] = None

    try:
      if flow_data.device_id:
        device_document = await self._find_device_by_id(flow_data.device_id.strip())
        if device_document is None:
          logger.warning(
            "Ignoring unknown explicit device_id during flow ingest | flow_id=%s | device_id=%s",
            flow_data.flow_id,
            flow_data.device_id,
          )

      if device_document is None:
        device_document = await self._find_device_by_source_ip(flow_data.source_ip)
    except Exception:
      logger.exception(
        "Device correlation lookup failed during flow ingest | flow_id=%s",
        flow_data.flow_id,
      )
      device_document = None

    if device_document is not None:
      device_id = device_document.get("device_id")
      device_user_id = device_document.get("user_id")
      if device_user_id:
        try:
          user_id = await self._find_existing_user_id(str(device_user_id))
        except Exception:
          logger.exception(
            "Device user validation failed during flow ingest | flow_id=%s | user_id=%s",
            flow_data.flow_id,
            device_user_id,
          )
          user_id = None

    if device_document is None and flow_data.user_id:
      logger.warning(
        "Ignoring explicit user_id without a registered device correlation | flow_id=%s",
        flow_data.flow_id,
      )

    return user_id, device_id, uploaded_by

  async def _recalculate_trust_score(self, user_id: str, device_id: str) -> None:
    try:
      await trust_score_service.calculate_trust_score(
        user_id=user_id,
        device_id=device_id,
        persist=True,
      )
    except Exception:
      logger.exception(
        "Zero Trust recalculation failed during flow ingest; continuing without changing firewall action | user_id=%s | device_id=%s",
        user_id,
        device_id,
      )

  def _build_document(
    self,
    flow_data: NetworkFlowIngestRequest,
    action: Optional[str],
    *,
    user_id: Optional[str] = None,
    device_id: Optional[str] = None,
    uploaded_by: Optional[str] = None,
  ) -> dict[str, Any]:
    captured_at = _parse_datetime(flow_data.captured_at)
    prediction = flow_data.prediction or {}
    is_threat = bool(flow_data.is_threat or prediction.get("is_attack", False))
    threat_label = flow_data.threat_label or prediction.get("attack_label")
    threat_confidence = flow_data.threat_confidence
    if threat_confidence is None and prediction.get("confidence") is not None:
      threat_confidence = float(prediction["confidence"])

    packet_count = flow_data.packet_count
    if packet_count is None and flow_data.total_packets is not None:
      packet_count = flow_data.total_packets

    metadata = dict(flow_data.metadata or {})
    if uploaded_by:
      metadata.setdefault("uploaded_by", uploaded_by)

    return {
      "flow_id": flow_data.flow_id,
      "source_ip": flow_data.source_ip,
      "destination_ip": flow_data.destination_ip,
      "source_mac": flow_data.source_mac,
      "destination_mac": flow_data.destination_mac,
      "source_port": flow_data.source_port,
      "destination_port": flow_data.destination_port,
      "protocol": flow_data.protocol,
      "captured_at": captured_at,
      "flow_start_time": _parse_datetime(flow_data.flow_start_time) if flow_data.flow_start_time else captured_at,
      "flow_end_time": _parse_datetime(flow_data.flow_end_time) if flow_data.flow_end_time else captured_at,
      "flow_duration": flow_data.flow_duration,
      "flow_packets_s": flow_data.flow_packets_s,
      "flow_bytes_s": flow_data.flow_bytes_s,
      "total_packets": flow_data.total_packets,
      "total_bytes": flow_data.total_bytes,
      "total_fwd_packets": flow_data.total_fwd_packets,
      "total_backward_packets": flow_data.total_backward_packets,
      "total_length_of_fwd_packets": flow_data.total_length_of_fwd_packets,
      "total_length_of_bwd_packets": flow_data.total_length_of_bwd_packets,
      "packet_count": packet_count,
      "bytes_sent": flow_data.bytes_sent,
      "bytes_received": flow_data.bytes_received,
      "action": action,
      "user_id": user_id,
      "device_id": device_id,
      "uploaded_by": uploaded_by,
      "features": flow_data.features,
      "metadata": metadata,
      "prediction": prediction or None,
      "is_threat": is_threat,
      "threat_label": threat_label,
      "threat_confidence": threat_confidence,
      "ingested_at": _utc_now(),
      "updated_at": _utc_now(),
    }

  async def _create_threat_alert(self, document: dict[str, Any]) -> None:
    if not document.get("is_threat"):
      return

    prediction = document.get("prediction") or {}
    flow_metadata = document.get("metadata") or {}
    threats_collection = get_threat_alerts_collection()

    existing_alert = await threats_collection.find_one(
      {
        "flow_id": document.get("flow_id"),
        "status": {"$in": ["open", "active", "investigating"]},
      }
    )
    if existing_alert:
      return

    alert_metadata = {
      "source": "ai_engine",
      "prediction": prediction,
      "analysis_source": flow_metadata.get("analysis_source"),
      "upload_id": flow_metadata.get("upload_id"),
      "analysis_id": flow_metadata.get("analysis_id"),
      "original_filename": flow_metadata.get("original_filename"),
    }

    alert_document = {
      "alert_id": str(uuid4()),
      "threat_type": document.get("threat_label") or prediction.get("attack_label") or "anomaly",
      "severity": _map_threat_severity(
        prediction.get("threat_level"),
        document.get("threat_confidence"),
      ),
      "status": "open",
      "source_ip": document.get("source_ip"),
      "destination_ip": document.get("destination_ip"),
      "flow_id": document.get("flow_id"),
      "user_id": document.get("user_id"),
      "device_id": document.get("device_id"),
      "confidence": document.get("threat_confidence"),
      "detected_at": document.get("captured_at", _utc_now()),
      "metadata": alert_metadata,
      "created_at": _utc_now(),
      "updated_at": _utc_now(),
    }

    await threats_collection.insert_one(alert_document)
    await websocket_manager.broadcast_threat_alert(alert_document)

  async def ingest_flow(
    self,
    flow_data: NetworkFlowIngestRequest,
    pending_trust_recalcs: Optional[set[tuple[str, str]]] = None,
  ) -> NetworkFlowIngestResponse:
    flows_collection = get_network_flows_collection()
    action = await self._resolve_firewall_action(flow_data)
    try:
      user_id, device_id, uploaded_by = await self._resolve_flow_correlation(flow_data)
    except Exception:
      logger.exception(
        "Zero Trust correlation failed during flow ingest; continuing without identity | flow_id=%s",
        flow_data.flow_id,
      )
      user_id, device_id, uploaded_by = None, None, None
    document = self._build_document(
      flow_data,
      action,
      user_id=user_id,
      device_id=device_id,
      uploaded_by=uploaded_by,
    )
    created = True

    try:
      await flows_collection.insert_one(document)
    except DuplicateKeyError:
      created = False
      document["updated_at"] = _utc_now()
      await flows_collection.update_one(
        {"flow_id": document["flow_id"]},
        {"$set": document},
      )

    if document.get("is_threat"):
      await self._create_threat_alert(document)

    if document.get("is_threat") and document.get("device_id") and document.get("user_id"):
      identity = (str(document["user_id"]), str(document["device_id"]))
      if pending_trust_recalcs is not None:
        pending_trust_recalcs.add(identity)
      else:
        await self._recalculate_trust_score(identity[0], identity[1])

    return NetworkFlowIngestResponse(
      success=True,
      message="Network flow ingested successfully" if created else "Network flow updated successfully",
      flow_id=document["flow_id"],
      is_threat=bool(document.get("is_threat")),
      created=created,
    )

  async def ingest_flows_batch(
    self,
    batch_data: NetworkFlowBatchIngestRequest,
  ) -> NetworkFlowBatchIngestResponse:
    ingested_count = 0
    threat_count = 0
    pending_trust_recalcs: set[tuple[str, str]] = set()

    for flow_data in batch_data.flows:
      result = await self.ingest_flow(flow_data, pending_trust_recalcs=pending_trust_recalcs)
      ingested_count += 1
      if result.is_threat:
        threat_count += 1

    for user_id, device_id in pending_trust_recalcs:
      await self._recalculate_trust_score(user_id, device_id)

    return NetworkFlowBatchIngestResponse(
      success=True,
      message="Network flow batch ingested successfully",
      total_flows=len(batch_data.flows),
      ingested_count=ingested_count,
      threat_count=threat_count,
    )


network_flow_service = NetworkFlowService()
