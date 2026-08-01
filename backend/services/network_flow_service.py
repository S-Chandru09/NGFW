from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from fastapi import HTTPException, status
from pymongo.errors import DuplicateKeyError

from core.websocket_manager import websocket_manager
from database import get_network_flows_collection, get_threat_alerts_collection
from schemas.network_flow import (
  NetworkFlowBatchIngestRequest,
  NetworkFlowBatchIngestResponse,
  NetworkFlowIngestRequest,
  NetworkFlowIngestResponse,
)


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


class NetworkFlowService:
  def _build_document(self, flow_data: NetworkFlowIngestRequest) -> dict[str, Any]:
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
      "action": flow_data.action,
      "features": flow_data.features,
      "metadata": flow_data.metadata,
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
      "confidence": document.get("threat_confidence"),
      "detected_at": document.get("captured_at", _utc_now()),
      "metadata": alert_metadata,
      "created_at": _utc_now(),
      "updated_at": _utc_now(),
    }

    await threats_collection.insert_one(alert_document)
    await websocket_manager.broadcast_threat_alert(alert_document)

  async def ingest_flow(self, flow_data: NetworkFlowIngestRequest) -> NetworkFlowIngestResponse:
    flows_collection = get_network_flows_collection()
    document = self._build_document(flow_data)
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

    for flow_data in batch_data.flows:
      result = await self.ingest_flow(flow_data)
      ingested_count += 1
      if result.is_threat:
        threat_count += 1

    return NetworkFlowBatchIngestResponse(
      success=True,
      message="Network flow batch ingested successfully",
      total_flows=len(batch_data.flows),
      ingested_count=ingested_count,
      threat_count=threat_count,
    )


network_flow_service = NetworkFlowService()
