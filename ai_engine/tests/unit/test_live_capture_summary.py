from unittest.mock import MagicMock

from services.live_capture import LiveCaptureService, LiveFlowDetection


def test_summarize_detections_counts_attack_types() -> None:
  service = LiveCaptureService(predictor=MagicMock())
  detections = [
    LiveFlowDetection(
      flow_id="flow-1",
      source_ip="10.0.0.1",
      destination_ip="10.0.0.2",
      source_port=12345,
      destination_port=80,
      protocol="TCP",
      total_packets=3,
      prediction={
        "attack_label": "DDoS",
        "confidence": 0.9,
        "is_attack": True,
        "threat_level": "high",
      },
      detected_at="2026-01-01T00:00:00+00:00",
    ),
    LiveFlowDetection(
      flow_id="flow-2",
      source_ip="10.0.0.3",
      destination_ip="10.0.0.4",
      source_port=443,
      destination_port=8443,
      protocol="TCP",
      total_packets=2,
      prediction={
        "attack_label": "BENIGN",
        "confidence": 0.2,
        "is_attack": False,
        "threat_level": "low",
      },
      detected_at="2026-01-01T00:00:01+00:00",
    ),
  ]

  summary = service._summarize_detections(detections)

  assert summary["malicious_flows"] == 1
  assert summary["benign_flows"] == 1
  assert summary["attack_counts"]["DDoS"] == 1
  assert summary["top_threat"]["attack_label"] == "DDoS"
