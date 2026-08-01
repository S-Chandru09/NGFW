from network.flow_generator import NetworkFlow
from network.sender import FeatureSender, SenderConfig


def _build_flow() -> NetworkFlow:
  return NetworkFlow(
    flow_id="10.0.0.1:12345|10.0.0.2:80|TCP",
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    src_mac=None,
    dst_mac=None,
    source_port=12345,
    destination_port=80,
    protocol="TCP",
    flow_start_time="2026-01-01T00:00:00+00:00",
    flow_end_time="2026-01-01T00:00:01+00:00",
    flow_duration=1_000_000.0,
    flow_packets_s=2.0,
    flow_bytes_s=200.0,
    total_packets=2,
    total_bytes=200,
    total_fwd_packets=2,
    total_backward_packets=0,
    total_length_of_fwd_packets=200,
    total_length_of_bwd_packets=0,
    features={
      "destination_port": 80,
      "source_port": 12345,
      "protocol": "TCP",
      "syn_flag_count": 1,
      "ack_flag_count": 1,
    },
  )


def test_build_flow_payload_marks_threat_predictions() -> None:
  sender = FeatureSender(SenderConfig(enabled=False))
  payload = sender.build_flow_payload(
    flow=_build_flow(),
    prediction={
      "attack_label": "DDoS",
      "confidence": 0.92,
      "is_attack": True,
      "threat_level": "high",
    },
    extra_metadata={"analysis_source": "pcap_upload", "upload_id": "upload-1"},
  )

  assert payload["is_threat"] is True
  assert payload["threat_label"] == "DDoS"
  assert payload["metadata"]["analysis_source"] == "pcap_upload"
  assert payload["metadata"]["upload_id"] == "upload-1"


def test_build_flow_payload_serializes_numpy_free_values() -> None:
  sender = FeatureSender(SenderConfig(enabled=False))
  payload = sender.build_flow_payload(flow=_build_flow())

  assert payload["flow_id"].startswith("10.0.0.1")
  assert payload["features"]["syn_flag_count"] == 1
