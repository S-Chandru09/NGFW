from services.network_flow_service import _map_threat_severity


def test_map_threat_severity_uses_prediction_level() -> None:
  assert _map_threat_severity("high", 0.4) == "high"
  assert _map_threat_severity("critical", None) == "critical"


def test_map_threat_severity_falls_back_to_confidence() -> None:
  assert _map_threat_severity(None, 0.95) == "critical"
  assert _map_threat_severity("", 0.8) == "high"
  assert _map_threat_severity(None, 0.6) == "medium"
  assert _map_threat_severity(None, 0.2) == "low"
