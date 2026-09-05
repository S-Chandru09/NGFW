from datetime import datetime, timedelta, timezone

from services.dashboard_service import (
  THREAT_SCORE_SATURATION_K,
  _attacks_today_match,
  _calculate_threat_level,
  _calculate_threat_score,
  _is_ingested_today,
)


def test_calculate_threat_level_buckets() -> None:
  assert _calculate_threat_level(0) == "safe"
  assert _calculate_threat_level(10) == "low"
  assert _calculate_threat_level(29) == "low"
  assert _calculate_threat_level(30) == "medium"
  assert _calculate_threat_level(40) == "medium"
  assert _calculate_threat_level(70) == "high"
  assert _calculate_threat_level(95) == "critical"


def test_threat_score_zero_alerts_is_zero() -> None:
  assert _calculate_threat_score(0, 0, 0, 0) == 0.0


def test_threat_score_ranks_severity_weights() -> None:
  critical_score = _calculate_threat_score(1, 0, 0, 0)
  high_score = _calculate_threat_score(0, 1, 0, 0)
  medium_score = _calculate_threat_score(0, 0, 1, 0)
  low_score = _calculate_threat_score(0, 0, 0, 1)

  assert critical_score > high_score > medium_score > low_score > 0


def test_threat_score_stays_within_zero_to_one_hundred() -> None:
  samples = [
    _calculate_threat_score(0, 0, 0, 0),
    _calculate_threat_score(1, 0, 0, 0),
    _calculate_threat_score(0, 20, 10, 10),
    _calculate_threat_score(0, 261, 32, 102),
    _calculate_threat_score(500, 5000, 5000, 5000),
  ]

  for score in samples:
    assert 0.0 <= score <= 100.0


def test_threat_score_moderate_volume_does_not_saturate() -> None:
  modest_high = _calculate_threat_score(0, 20, 0, 0)
  previous_saturating_mix = _calculate_threat_score(10, 10, 10, 10)

  assert modest_high < 50
  assert previous_saturating_mix < 50


def test_threat_score_extreme_volume_approaches_but_does_not_exceed_100() -> None:
  high_volume = _calculate_threat_score(0, 261, 0, 0)
  extreme_volume = _calculate_threat_score(0, 2000, 0, 0)

  assert high_volume < 95
  assert 99 < extreme_volume <= 100
  assert THREAT_SCORE_SATURATION_K == 2000.0


def test_threat_score_does_not_alter_severity_counts() -> None:
  critical_count = 0
  high_count = 261
  medium_count = 32
  low_count = 102

  score = _calculate_threat_score(critical_count, high_count, medium_count, low_count)

  assert critical_count == 0
  assert high_count == 261
  assert medium_count == 32
  assert low_count == 102
  assert 0 < score < 100


def test_attacks_today_counts_alert_created_today_with_yesterday_detected_at() -> None:
  now = datetime(2026, 9, 5, 12, 36, tzinfo=timezone.utc)
  created_today = now - timedelta(minutes=10)
  detected_yesterday = datetime(2026, 9, 4, 12, 34, tzinfo=timezone.utc)

  assert _is_ingested_today(created_today, now) is True
  assert detected_yesterday < _attacks_today_match(now)["created_at"]["$gte"]


def test_attacks_today_excludes_alert_created_yesterday() -> None:
  now = datetime(2026, 9, 5, 12, 36, tzinfo=timezone.utc)
  created_yesterday = datetime(2026, 9, 4, 18, 4, tzinfo=timezone.utc)

  assert _is_ingested_today(created_yesterday, now) is False


def test_attacks_today_match_uses_created_at_not_detected_at() -> None:
  now = datetime(2026, 9, 5, 12, 36, tzinfo=timezone.utc)
  match = _attacks_today_match(now)

  assert match == {
    "created_at": {"$gte": datetime(2026, 9, 5, 0, 0, tzinfo=timezone.utc)},
  }
  assert "detected_at" not in match
