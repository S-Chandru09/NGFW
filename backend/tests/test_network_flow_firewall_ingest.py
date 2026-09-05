from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from schemas.network_flow import NetworkFlowIngestRequest
from services.network_flow_service import NetworkFlowService
from schemas.firewall_engine import FirewallEvaluationResult
from models.firewall_rule import FirewallProtocol


def _empty_collection() -> AsyncMock:
  collection = AsyncMock()
  collection.find_one = AsyncMock(return_value=None)
  collection.insert_one = AsyncMock()
  collection.update_one = AsyncMock()
  return collection


def _https_flow(**overrides) -> NetworkFlowIngestRequest:
  payload = {
    "flow_id": "test-flow-https",
    "source_ip": "192.168.1.101",
    "destination_ip": "51.132.193.105",
    "source_port": 54199,
    "destination_port": 443,
    "protocol": "TCP",
    "is_threat": True,
    "threat_label": "PortScan",
    "threat_confidence": 0.9,
    "prediction": {
      "attack_label": "PortScan",
      "confidence": 0.9,
      "is_attack": True,
      "threat_level": "high",
    },
  }
  payload.update(overrides)
  return NetworkFlowIngestRequest(**payload)


def _evaluation(decision: str) -> FirewallEvaluationResult:
  return FirewallEvaluationResult(
    flow_id="test-flow-https",
    source_ip="192.168.1.101",
    destination_ip="51.132.193.105",
    source_port=54199,
    destination_port=443,
    protocol=FirewallProtocol.TCP,
    decision=decision,
    is_allowed=decision in {"allow", "whitelist"},
    matched_rule=None,
    match_details=[],
    evaluated_at=datetime(2026, 9, 5, 7, 0, tzinfo=timezone.utc),
  )


@pytest.mark.asyncio
async def test_ingest_matching_block_rule_persists_action_block() -> None:
  service = NetworkFlowService()
  flows = AsyncMock()
  threats = AsyncMock()
  threats.find_one.return_value = None
  flows.insert_one = AsyncMock()

  with (
    patch("services.network_flow_service.get_network_flows_collection", return_value=flows),
    patch("services.network_flow_service.get_threat_alerts_collection", return_value=threats),
    patch("services.network_flow_service.get_devices_collection", return_value=_empty_collection()),
    patch("services.network_flow_service.get_users_collection", return_value=_empty_collection()),
    patch("services.network_flow_service.get_packet_uploads_collection", return_value=_empty_collection()),
    patch(
      "services.network_flow_service.firewall_engine.evaluate_flow",
      new=AsyncMock(return_value=_evaluation("block")),
    ),
    patch("services.network_flow_service.websocket_manager.broadcast_threat_alert", new=AsyncMock()),
  ):
    result = await service.ingest_flow(_https_flow())

  document = flows.insert_one.await_args.args[0]
  assert result.success is True
  assert document["action"] == "block"
  assert document["is_threat"] is True
  assert document["threat_label"] == "PortScan"
  threats.insert_one.assert_awaited_once()


@pytest.mark.asyncio
async def test_ingest_nonmatching_flow_is_not_blocked() -> None:
  service = NetworkFlowService()
  flows = AsyncMock()
  threats = AsyncMock()
  threats.find_one.return_value = None

  with (
    patch("services.network_flow_service.get_network_flows_collection", return_value=flows),
    patch("services.network_flow_service.get_threat_alerts_collection", return_value=threats),
    patch("services.network_flow_service.get_devices_collection", return_value=_empty_collection()),
    patch("services.network_flow_service.get_users_collection", return_value=_empty_collection()),
    patch("services.network_flow_service.get_packet_uploads_collection", return_value=_empty_collection()),
    patch(
      "services.network_flow_service.firewall_engine.evaluate_flow",
      new=AsyncMock(return_value=_evaluation("allow")),
    ),
    patch("services.network_flow_service.websocket_manager.broadcast_threat_alert", new=AsyncMock()),
  ):
    await service.ingest_flow(
      _https_flow(destination_ip="8.8.8.8", is_threat=False, threat_label=None, prediction=None)
    )

  document = flows.insert_one.await_args.args[0]
  assert document["action"] == "allow"
  assert document["is_threat"] is False
  threats.insert_one.assert_not_called()


@pytest.mark.asyncio
async def test_threat_alert_still_created_for_blocked_malicious_flow() -> None:
  service = NetworkFlowService()
  flows = AsyncMock()
  threats = AsyncMock()
  threats.find_one.return_value = None

  with (
    patch("services.network_flow_service.get_network_flows_collection", return_value=flows),
    patch("services.network_flow_service.get_threat_alerts_collection", return_value=threats),
    patch("services.network_flow_service.get_devices_collection", return_value=_empty_collection()),
    patch("services.network_flow_service.get_users_collection", return_value=_empty_collection()),
    patch("services.network_flow_service.get_packet_uploads_collection", return_value=_empty_collection()),
    patch(
      "services.network_flow_service.firewall_engine.evaluate_flow",
      new=AsyncMock(return_value=_evaluation("block")),
    ),
    patch("services.network_flow_service.websocket_manager.broadcast_threat_alert", new=AsyncMock()) as broadcast,
  ):
    await service.ingest_flow(_https_flow())

  alert = threats.insert_one.await_args.args[0]
  assert alert["threat_type"] == "PortScan"
  assert alert["source_ip"] == "192.168.1.101"
  broadcast.assert_awaited_once()


@pytest.mark.asyncio
async def test_explicit_action_skips_firewall_evaluation() -> None:
  service = NetworkFlowService()
  flows = AsyncMock()
  evaluate = AsyncMock()

  with (
    patch("services.network_flow_service.get_network_flows_collection", return_value=flows),
    patch("services.network_flow_service.get_threat_alerts_collection", new=AsyncMock()),
    patch("services.network_flow_service.get_devices_collection", return_value=_empty_collection()),
    patch("services.network_flow_service.get_users_collection", return_value=_empty_collection()),
    patch("services.network_flow_service.get_packet_uploads_collection", return_value=_empty_collection()),
    patch("services.network_flow_service.firewall_engine.evaluate_flow", new=evaluate),
  ):
    await service.ingest_flow(_https_flow(action="allow", is_threat=False, prediction=None, threat_label=None))

  evaluate.assert_not_called()
  assert flows.insert_one.await_args.args[0]["action"] == "allow"


@pytest.mark.asyncio
async def test_firewall_failure_fail_open_does_not_block() -> None:
  service = NetworkFlowService()
  flows = AsyncMock()

  with (
    patch("services.network_flow_service.get_network_flows_collection", return_value=flows),
    patch("services.network_flow_service.get_threat_alerts_collection", new=AsyncMock()),
    patch("services.network_flow_service.get_devices_collection", return_value=_empty_collection()),
    patch("services.network_flow_service.get_users_collection", return_value=_empty_collection()),
    patch("services.network_flow_service.get_packet_uploads_collection", return_value=_empty_collection()),
    patch(
      "services.network_flow_service.firewall_engine.evaluate_flow",
      new=AsyncMock(side_effect=RuntimeError("engine unavailable")),
    ),
  ):
    await service.ingest_flow(_https_flow(is_threat=False, prediction=None, threat_label=None))

  assert flows.insert_one.await_args.args[0]["action"] is None
