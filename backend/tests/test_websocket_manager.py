from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from core.websocket_manager import WebSocketManager, _serialize_payload


@pytest.mark.asyncio
async def test_broadcast_delivers_to_active_connections() -> None:
  manager = WebSocketManager()
  websocket = AsyncMock()
  websocket.send_text = AsyncMock()
  manager._connections.add(websocket)

  delivered = await manager.broadcast({"type": "test", "data": {"ok": True}})

  assert delivered == 1
  websocket.send_text.assert_awaited_once()


@pytest.mark.asyncio
async def test_broadcast_threat_alert_shapes_message() -> None:
  manager = WebSocketManager()
  websocket = AsyncMock()
  websocket.send_text = AsyncMock()
  manager._connections.add(websocket)

  detected_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
  await manager.broadcast_threat_alert(
    {
      "alert_id": "alert-1",
      "threat_type": "DDoS",
      "severity": "high",
      "status": "open",
      "source_ip": "10.0.0.1",
      "destination_ip": "10.0.0.2",
      "flow_id": "flow-1",
      "confidence": 0.91,
      "detected_at": detected_at,
      "metadata": {
        "analysis_source": "pcap_upload",
        "upload_id": "upload-1",
        "original_filename": "attack.pcap",
      },
    }
  )

  sent_payload = websocket.send_text.await_args.args[0]
  assert '"type": "threat_alert"' in sent_payload
  assert "DDoS" in sent_payload
  assert "attack.pcap" in sent_payload


def test_serialize_payload_converts_datetime() -> None:
  payload = _serialize_payload({"detected_at": datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)})
  assert payload["detected_at"] == "2026-01-01T12:00:00+00:00"
