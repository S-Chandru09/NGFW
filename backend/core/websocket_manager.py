import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import WebSocket

logger = logging.getLogger("ai-ngfw.websocket")


def _serialize_value(value: Any) -> Any:
  if isinstance(value, datetime):
    if value.tzinfo is None:
      value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()
  return value


def _serialize_payload(payload: dict[str, Any]) -> dict[str, Any]:
  return {key: _serialize_value(value) for key, value in payload.items()}


class WebSocketManager:
  """Manage dashboard WebSocket connections and broadcast threat alerts."""

  def __init__(self) -> None:
    self._connections: set[WebSocket] = set()
    self._lock = asyncio.Lock()

  @property
  def connection_count(self) -> int:
    return len(self._connections)

  async def connect(self, websocket: WebSocket) -> None:
    await websocket.accept()
    async with self._lock:
      self._connections.add(websocket)
    logger.info("WebSocket client connected | active=%s", self.connection_count)

  async def disconnect(self, websocket: WebSocket) -> None:
    async with self._lock:
      self._connections.discard(websocket)
    logger.info("WebSocket client disconnected | active=%s", self.connection_count)

  async def _send_json(self, websocket: WebSocket, payload: dict[str, Any]) -> bool:
    try:
      await websocket.send_text(json.dumps(payload, default=_serialize_value))
      return True
    except Exception:
      return False

  async def broadcast(self, payload: dict[str, Any]) -> int:
    if not self._connections:
      return 0

    async with self._lock:
      connections = list(self._connections)

    delivered = 0
    stale_connections: list[WebSocket] = []

    for connection in connections:
      sent = await self._send_json(connection, payload)
      if sent:
        delivered += 1
      else:
        stale_connections.append(connection)

    if stale_connections:
      async with self._lock:
        for connection in stale_connections:
          self._connections.discard(connection)

    return delivered

  async def broadcast_threat_alert(self, alert: dict[str, Any]) -> int:
    metadata = alert.get("metadata") or {}
    message = {
      "type": "threat_alert",
      "data": _serialize_payload(
        {
          "alert_id": alert.get("alert_id"),
          "threat_type": alert.get("threat_type"),
          "severity": alert.get("severity"),
          "status": alert.get("status"),
          "source_ip": alert.get("source_ip"),
          "destination_ip": alert.get("destination_ip"),
          "flow_id": alert.get("flow_id"),
          "confidence": alert.get("confidence"),
          "detected_at": alert.get("detected_at"),
          "analysis_source": metadata.get("analysis_source"),
          "upload_id": metadata.get("upload_id"),
          "original_filename": metadata.get("original_filename"),
          "session_id": metadata.get("session_id"),
        }
      ),
    }
    delivered = await self.broadcast(message)
    logger.info(
      "Threat alert broadcast | alert_id=%s | delivered=%s",
      alert.get("alert_id"),
      delivered,
    )
    return delivered

  async def send_connection_ack(self, websocket: WebSocket) -> None:
    await self._send_json(
      websocket,
      {
        "type": "connection_ack",
        "data": {
          "message": "Connected to AI-NGFW real-time threat alerts",
          "subscribed_events": ["threat_alert"],
        },
      },
    )


websocket_manager = WebSocketManager()
