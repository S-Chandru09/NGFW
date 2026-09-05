import pytest
from pydantic import ValidationError

from schemas.network_flow import NetworkFlowIngestRequest

IPV4_SCOPED_FLOW_ID = "550e8400-e29b-41d4-a716-446655440000:10.0.0.1:12345|10.0.0.2:80|TCP"
IPV6_SCOPED_FLOW_ID = (
  "550e8400-e29b-41d4-a716-446655440000:"
  "2001:0db8:85a3:0000:0000:8a2e:0370:7334:65535|"
  "2001:0db8:0000:0000:0000:0000:0000:0001:65535|TCP"
)


def test_network_flow_ingest_accepts_ipv4_scoped_flow_id() -> None:
  request = NetworkFlowIngestRequest(flow_id=IPV4_SCOPED_FLOW_ID)

  assert request.flow_id == IPV4_SCOPED_FLOW_ID
  assert len(request.flow_id) < 100


def test_network_flow_ingest_accepts_ipv6_scoped_flow_id() -> None:
  assert 130 <= len(IPV6_SCOPED_FLOW_ID) <= 150

  request = NetworkFlowIngestRequest(flow_id=IPV6_SCOPED_FLOW_ID)

  assert request.flow_id == IPV6_SCOPED_FLOW_ID


def test_network_flow_ingest_rejects_empty_flow_id() -> None:
  with pytest.raises(ValidationError) as exc_info:
    NetworkFlowIngestRequest(flow_id="")

  assert "flow_id" in str(exc_info.value)


def test_network_flow_ingest_rejects_flow_id_longer_than_255() -> None:
  with pytest.raises(ValidationError) as exc_info:
    NetworkFlowIngestRequest(flow_id="a" * 256)

  assert "flow_id" in str(exc_info.value)


def test_network_flow_ingest_optional_correlation_fields_default_to_none() -> None:
  request = NetworkFlowIngestRequest(flow_id=IPV4_SCOPED_FLOW_ID)

  assert request.user_id is None
  assert request.device_id is None
  assert request.uploaded_by is None
