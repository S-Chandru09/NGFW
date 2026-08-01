from services.dashboard_service import _calculate_threat_level, _calculate_threat_score


def test_calculate_threat_level_buckets() -> None:
  assert _calculate_threat_level(0) == "safe"
  assert _calculate_threat_level(10) == "low"
  assert _calculate_threat_level(40) == "medium"
  assert _calculate_threat_level(70) == "high"
  assert _calculate_threat_level(95) == "critical"


def test_calculate_threat_score_is_capped_at_100() -> None:
  score = _calculate_threat_score(critical_count=10, high_count=10, medium_count=10, low_count=10)
  assert score == 100.0
