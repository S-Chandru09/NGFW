from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from inspect import getsource
from unittest.mock import AsyncMock, patch

import pytest

from models.firewall_rule import FirewallProtocol
from schemas.firewall_engine import FirewallEvaluationResult
from schemas.network_flow import NetworkFlowBatchIngestRequest, NetworkFlowIngestRequest
from services import network_flow_service as network_flow_service_module
from services.network_flow_service import NetworkFlowService


EXISTING_DEVICE = {
  "device_id": "existing-device",
  "user_id": "existing-user",
  "ip_address": "192.168.1.101",
}


def _empty_collection() -> AsyncMock:
  collection = AsyncMock()
  collection.find_one = AsyncMock(return_value=None)
  collection.insert_one = AsyncMock()
  collection.update_one = AsyncMock()
  collection.update_many = AsyncMock()
  collection.insert_many = AsyncMock()
  return collection


def _collection_with_find(side_effect) -> AsyncMock:
  collection = _empty_collection()
  collection.find_one = AsyncMock(side_effect=side_effect)
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


async def _device_find(query: dict):
  if query.get("device_id") == EXISTING_DEVICE["device_id"]:
    return EXISTING_DEVICE
  if query.get("ip_address") == EXISTING_DEVICE["ip_address"]:
    return EXISTING_DEVICE
  return None


async def _user_find(query: dict):
  if query.get("username") == "existing-user":
    return {"_id": "existing-user"}
  return None


@contextmanager
def _ingest_patches(
  flows,
  threats,
  *,
  devices=None,
  users=None,
  uploads=None,
  firewall_decision: str = "allow",
  calculate=None,
):
  with ExitStack() as stack:
    stack.enter_context(patch("services.network_flow_service.get_network_flows_collection", return_value=flows))
    stack.enter_context(patch("services.network_flow_service.get_threat_alerts_collection", return_value=threats))
    stack.enter_context(
      patch(
        "services.network_flow_service.get_devices_collection",
        return_value=devices if devices is not None else _empty_collection(),
      )
    )
    stack.enter_context(
      patch(
        "services.network_flow_service.get_users_collection",
        return_value=users if users is not None else _empty_collection(),
      )
    )
    stack.enter_context(
      patch(
        "services.network_flow_service.get_packet_uploads_collection",
        return_value=uploads if uploads is not None else _empty_collection(),
      )
    )
    stack.enter_context(
      patch(
        "services.network_flow_service.firewall_engine.evaluate_flow",
        new=AsyncMock(return_value=_evaluation(firewall_decision)),
      )
    )
    stack.enter_context(patch("services.network_flow_service.websocket_manager.broadcast_threat_alert", new=AsyncMock()))
    stack.enter_context(
      patch(
        "services.network_flow_service.trust_score_service.calculate_trust_score",
        new=calculate if calculate is not None else AsyncMock(),
      )
    )
    yield


@pytest.mark.asyncio
async def test_known_device_threat_correlates_and_recalculates_once() -> None:
  service = NetworkFlowService()
  flows = _empty_collection()
  threats = _empty_collection()
  calculate = AsyncMock()

  with _ingest_patches(
    flows,
    threats,
    devices=_collection_with_find(_device_find),
    users=_collection_with_find(_user_find),
    calculate=calculate,
  ):
    await service.ingest_flow(_https_flow())

  document = flows.insert_one.await_args.args[0]
  alert = threats.insert_one.await_args.args[0]
  assert document["device_id"] == "existing-device"
  assert document["user_id"] == "existing-user"
  assert alert["device_id"] == "existing-device"
  assert alert["user_id"] == "existing-user"
  calculate.assert_awaited_once_with(
    user_id="existing-user",
    device_id="existing-device",
    persist=True,
  )
  flows.insert_many.assert_not_called()
  threats.update_many.assert_not_called()


@pytest.mark.asyncio
async def test_unknown_source_ip_does_not_invent_identity_or_recalculate() -> None:
  service = NetworkFlowService()
  flows = _empty_collection()
  threats = _empty_collection()
  calculate = AsyncMock()

  with _ingest_patches(flows, threats, calculate=calculate):
    result = await service.ingest_flow(_https_flow(source_ip="10.9.9.9"))

  document = flows.insert_one.await_args.args[0]
  alert = threats.insert_one.await_args.args[0]
  assert result.success is True
  assert document["device_id"] is None
  assert document["user_id"] is None
  assert alert["device_id"] is None
  assert alert["user_id"] is None
  calculate.assert_not_called()


@pytest.mark.asyncio
async def test_non_threat_flow_skips_alert_and_trust() -> None:
  service = NetworkFlowService()
  flows = _empty_collection()
  threats = _empty_collection()
  calculate = AsyncMock()

  with _ingest_patches(
    flows,
    threats,
    devices=_collection_with_find(_device_find),
    users=_collection_with_find(_user_find),
    firewall_decision="allow",
    calculate=calculate,
  ):
    await service.ingest_flow(_https_flow(is_threat=False, threat_label=None, prediction=None))

  document = flows.insert_one.await_args.args[0]
  assert document["action"] == "allow"
  threats.insert_one.assert_not_called()
  calculate.assert_not_called()


@pytest.mark.asyncio
async def test_uploaded_by_is_attribution_only() -> None:
  service = NetworkFlowService()
  flows = _empty_collection()
  threats = _empty_collection()
  calculate = AsyncMock()
  uploads = _collection_with_find(
    lambda query: {"uploaded_by": "analyst-uploader"} if query.get("upload_id") == "upload-1" else None
  )

  with _ingest_patches(flows, threats, uploads=uploads, calculate=calculate):
    await service.ingest_flow(
      _https_flow(
        uploaded_by="analyst-uploader",
        metadata={"upload_id": "upload-1"},
      )
    )

  document = flows.insert_one.await_args.args[0]
  assert document["uploaded_by"] == "analyst-uploader"
  assert document["metadata"]["uploaded_by"] == "analyst-uploader"
  assert document["user_id"] != document["uploaded_by"]
  assert document["user_id"] is None
  calculate.assert_not_called()


@pytest.mark.asyncio
async def test_explicit_existing_device_is_validated() -> None:
  service = NetworkFlowService()
  flows = _empty_collection()
  threats = _empty_collection()
  calculate = AsyncMock()

  with _ingest_patches(
    flows,
    threats,
    devices=_collection_with_find(_device_find),
    users=_collection_with_find(_user_find),
    calculate=calculate,
  ):
    await service.ingest_flow(_https_flow(source_ip="203.0.113.10", device_id="existing-device"))

  document = flows.insert_one.await_args.args[0]
  assert document["device_id"] == "existing-device"
  assert document["user_id"] == "existing-user"
  calculate.assert_awaited_once_with(
    user_id="existing-user",
    device_id="existing-device",
    persist=True,
  )


@pytest.mark.asyncio
async def test_firewall_block_is_unchanged_by_zero_trust() -> None:
  service = NetworkFlowService()
  flows = _empty_collection()
  threats = _empty_collection()

  with _ingest_patches(
    flows,
    threats,
    devices=_collection_with_find(_device_find),
    users=_collection_with_find(_user_find),
    firewall_decision="block",
  ):
    await service.ingest_flow(_https_flow())

  assert flows.insert_one.await_args.args[0]["action"] == "block"


@pytest.mark.asyncio
async def test_firewall_allow_is_unchanged_by_zero_trust() -> None:
  service = NetworkFlowService()
  flows = _empty_collection()
  threats = _empty_collection()

  with _ingest_patches(
    flows,
    threats,
    devices=_collection_with_find(_device_find),
    users=_collection_with_find(_user_find),
    firewall_decision="allow",
  ):
    await service.ingest_flow(_https_flow(destination_ip="8.8.8.8"))

  assert flows.insert_one.await_args.args[0]["action"] == "allow"


@pytest.mark.asyncio
async def test_trust_calculation_failure_is_fail_open() -> None:
  service = NetworkFlowService()
  flows = _empty_collection()
  threats = _empty_collection()
  calculate = AsyncMock(side_effect=RuntimeError("trust unavailable"))

  with _ingest_patches(
    flows,
    threats,
    devices=_collection_with_find(_device_find),
    users=_collection_with_find(_user_find),
    firewall_decision="block",
    calculate=calculate,
  ):
    result = await service.ingest_flow(_https_flow())

  document = flows.insert_one.await_args.args[0]
  assert result.success is True
  assert document["action"] == "block"
  threats.insert_one.assert_awaited_once()


@pytest.mark.asyncio
async def test_batch_recalculates_unique_device_once() -> None:
  service = NetworkFlowService()
  flows = _empty_collection()
  threats = _empty_collection()
  calculate = AsyncMock()
  batch = NetworkFlowBatchIngestRequest(
    flows=[
      _https_flow(flow_id="threat-1"),
      _https_flow(flow_id="threat-2"),
      _https_flow(flow_id="threat-3"),
    ]
  )

  with _ingest_patches(
    flows,
    threats,
    devices=_collection_with_find(_device_find),
    users=_collection_with_find(_user_find),
    calculate=calculate,
  ):
    await service.ingest_flows_batch(batch)

  assert flows.insert_one.await_count == 3
  assert threats.insert_one.await_count == 3
  calculate.assert_awaited_once_with(
    user_id="existing-user",
    device_id="existing-device",
    persist=True,
  )


def test_correlation_does_not_add_historical_migration_queries() -> None:
  source = getsource(network_flow_service_module)
  assert "update_many(" not in source
  ingest_source = getsource(NetworkFlowService.ingest_flow)
  assert '{"flow_id": document["flow_id"]}' in ingest_source
