from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from config import settings
from database import (
  get_devices_collection,
  get_firewall_rules_collection,
  get_network_flows_collection,
  get_threat_alerts_collection,
)
from schemas.dashboard import (
  AttackCountBreakdown,
  AttackCountResponse,
  AttackTypeItem,
  DashboardKPI,
  DashboardStatisticsData,
  DashboardStatisticsResponse,
  HourlyTrafficPoint,
  ProtocolTraffic,
  ThreatLevelBreakdown,
  ThreatLevelResponse,
  TopAttackTypesResponse,
  ThreatAlertItem,
  TrafficSummaryResponse,
)


def _utc_now() -> datetime:
  return datetime.now(timezone.utc)


def _hours_ago(hours: int) -> datetime:
  return _utc_now() - timedelta(hours=hours)


def _start_of_day() -> datetime:
  now = _utc_now()
  return now.replace(hour=0, minute=0, second=0, microsecond=0)


def _start_of_week() -> datetime:
  now = _utc_now()
  start = now - timedelta(days=now.weekday())
  return start.replace(hour=0, minute=0, second=0, microsecond=0)


def _start_of_month() -> datetime:
  now = _utc_now()
  return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _calculate_threat_level(score: float) -> str:
  if score >= 80:
    return "critical"
  if score >= 60:
    return "high"
  if score >= 35:
    return "medium"
  if score > 0:
    return "low"
  return "safe"


def _calculate_threat_score(
  critical_count: int,
  high_count: int,
  medium_count: int,
  low_count: int,
) -> float:
  weighted_score = (
    critical_count * 25
    + high_count * 15
    + medium_count * 8
    + low_count * 3
  )
  return min(float(weighted_score), 100.0)


class DashboardService:
  async def get_traffic_summary(self, period_hours: int = 24) -> TrafficSummaryResponse:
    flows_collection = get_network_flows_collection()
    threats_collection = get_threat_alerts_collection()
    since = _hours_ago(period_hours)
    flow_filter = {"captured_at": {"$gte": since}}

    total_flows = await flows_collection.count_documents(flow_filter)
    threat_flows = await flows_collection.count_documents({**flow_filter, "is_threat": True})
    blocked_flows = await flows_collection.count_documents({**flow_filter, "action": "block"})
    allowed_flows = max(total_flows - blocked_flows, 0)

    traffic_pipeline = [
      {"$match": flow_filter},
      {
        "$group": {
          "_id": None,
          "total_bytes": {"$sum": {"$ifNull": ["$total_bytes", 0]}},
          "total_packets": {"$sum": {"$ifNull": ["$packet_count", 0]}},
          "inbound_bytes": {"$sum": {"$ifNull": ["$bytes_received", 0]}},
          "outbound_bytes": {"$sum": {"$ifNull": ["$bytes_sent", 0]}},
          "source_ips": {"$addToSet": "$source_ip"},
          "destination_ips": {"$addToSet": "$destination_ip"},
        }
      },
    ]
    traffic_result = await flows_collection.aggregate(traffic_pipeline).to_list(length=1)
    traffic_data = traffic_result[0] if traffic_result else {}

    protocol_pipeline = [
      {"$match": flow_filter},
      {
        "$group": {
          "_id": {"$ifNull": ["$protocol", "unknown"]},
          "flow_count": {"$sum": 1},
          "total_bytes": {"$sum": {"$ifNull": ["$total_bytes", 0]}},
        }
      },
      {"$sort": {"flow_count": -1}},
    ]
    protocol_results = await flows_collection.aggregate(protocol_pipeline).to_list(length=20)
    total_bytes = traffic_data.get("total_bytes", 0) or 0

    protocols = []
    for item in protocol_results:
      bytes_count = item.get("total_bytes", 0) or 0
      percentage = round((bytes_count / total_bytes) * 100, 2) if total_bytes > 0 else 0.0
      protocols.append(
        ProtocolTraffic(
          protocol=str(item.get("_id", "unknown")),
          flow_count=item.get("flow_count", 0),
          total_bytes=bytes_count,
          percentage=percentage,
        )
      )

    hourly_trend = await self._build_hourly_trend(flows_collection, threats_collection, period_hours)

    return TrafficSummaryResponse(
      success=True,
      message="Traffic summary retrieved successfully",
      total_flows=total_flows,
      total_bytes=total_bytes,
      total_packets=traffic_data.get("total_packets", 0) or 0,
      inbound_bytes=traffic_data.get("inbound_bytes", 0) or 0,
      outbound_bytes=traffic_data.get("outbound_bytes", 0) or 0,
      allowed_flows=allowed_flows,
      blocked_flows=blocked_flows,
      threat_flows=threat_flows,
      unique_source_ips=len(traffic_data.get("source_ips", []) or []),
      unique_destination_ips=len(traffic_data.get("destination_ips", []) or []),
      protocols=protocols,
      hourly_trend=hourly_trend,
      period_hours=period_hours,
      generated_at=_utc_now(),
    )

  async def _build_hourly_trend(
    self,
    flows_collection,
    threats_collection,
    period_hours: int,
  ) -> list[HourlyTrafficPoint]:
    since = _hours_ago(period_hours)

    flow_pipeline = [
      {"$match": {"captured_at": {"$gte": since}}},
      {
        "$group": {
          "_id": {
            "$dateToString": {
              "format": "%Y-%m-%d %H:00",
              "date": "$captured_at",
            }
          },
          "flow_count": {"$sum": 1},
          "total_bytes": {"$sum": {"$ifNull": ["$total_bytes", 0]}},
        }
      },
      {"$sort": {"_id": 1}},
    ]
    flow_results = await flows_collection.aggregate(flow_pipeline).to_list(length=period_hours + 1)
    flow_map = {item["_id"]: item for item in flow_results}

    threat_pipeline = [
      {"$match": {"detected_at": {"$gte": since}}},
      {
        "$group": {
          "_id": {
            "$dateToString": {
              "format": "%Y-%m-%d %H:00",
              "date": "$detected_at",
            }
          },
          "threat_count": {"$sum": 1},
        }
      },
      {"$sort": {"_id": 1}},
    ]
    threat_results = await threats_collection.aggregate(threat_pipeline).to_list(length=period_hours + 1)
    threat_map = {item["_id"]: item.get("threat_count", 0) for item in threat_results}

    hourly_points: list[HourlyTrafficPoint] = []
    for hour_offset in range(period_hours, -1, -1):
      hour_time = _utc_now() - timedelta(hours=hour_offset)
      hour_key = hour_time.strftime("%Y-%m-%d %H:00")
      flow_item = flow_map.get(hour_key, {})
      hourly_points.append(
        HourlyTrafficPoint(
          hour=hour_key,
          flow_count=flow_item.get("flow_count", 0),
          total_bytes=flow_item.get("total_bytes", 0) or 0,
          threat_count=threat_map.get(hour_key, 0),
        )
      )

    return hourly_points

  async def get_attack_count(self) -> AttackCountResponse:
    threats_collection = get_threat_alerts_collection()
    now = _utc_now()
    today_start = _start_of_day()
    week_start = _start_of_week()
    month_start = _start_of_month()

    total_attacks = await threats_collection.count_documents({})
    attacks_today = await threats_collection.count_documents({"detected_at": {"$gte": today_start}})
    attacks_this_week = await threats_collection.count_documents({"detected_at": {"$gte": week_start}})
    attacks_this_month = await threats_collection.count_documents({"detected_at": {"$gte": month_start}})
    blocked_attacks = await threats_collection.count_documents({"status": "blocked"})
    active_alerts = await threats_collection.count_documents({"status": {"$in": ["open", "active", "investigating"]}})
    resolved_alerts = await threats_collection.count_documents({"status": {"$in": ["resolved", "closed"]}})

    severity_pipeline = [
      {
        "$group": {
          "_id": {"$toLower": {"$ifNull": ["$severity", "unknown"]}},
          "count": {"$sum": 1},
        }
      },
    ]
    severity_results = await threats_collection.aggregate(severity_pipeline).to_list(length=10)
    severity_map = {item["_id"]: item.get("count", 0) for item in severity_results}

    breakdown = AttackCountBreakdown(
      total_attacks=total_attacks,
      attacks_today=attacks_today,
      attacks_this_week=attacks_this_week,
      attacks_this_month=attacks_this_month,
      blocked_attacks=blocked_attacks,
      active_alerts=active_alerts,
      resolved_alerts=resolved_alerts,
      critical_attacks=severity_map.get("critical", 0),
      high_attacks=severity_map.get("high", 0),
      medium_attacks=severity_map.get("medium", 0),
      low_attacks=severity_map.get("low", 0),
    )

    return AttackCountResponse(
      success=True,
      message="Attack count retrieved successfully",
      data=breakdown,
      generated_at=now,
    )

  async def get_threat_level(self, period_hours: int = 24) -> ThreatLevelResponse:
    threats_collection = get_threat_alerts_collection()
    since = _hours_ago(period_hours)
    previous_since = _hours_ago(period_hours * 2)

    current_filter = {"detected_at": {"$gte": since}}
    previous_filter = {"detected_at": {"$gte": previous_since, "$lt": since}}

    current_severity = await self._get_severity_counts(threats_collection, current_filter)
    previous_severity = await self._get_severity_counts(threats_collection, previous_filter)

    current_score = _calculate_threat_score(
      current_severity.get("critical", 0),
      current_severity.get("high", 0),
      current_severity.get("medium", 0),
      current_severity.get("low", 0),
    )
    previous_score = _calculate_threat_score(
      previous_severity.get("critical", 0),
      previous_severity.get("high", 0),
      previous_severity.get("medium", 0),
      previous_severity.get("low", 0),
    )

    if current_score > previous_score:
      risk_trend = "increasing"
    elif current_score < previous_score:
      risk_trend = "decreasing"
    else:
      risk_trend = "stable"

    last_incident = await threats_collection.find_one(
      {},
      sort=[("detected_at", -1)],
    )

    breakdown = ThreatLevelBreakdown(
      overall_score=round(current_score, 2),
      overall_level=_calculate_threat_level(current_score),
      critical_count=current_severity.get("critical", 0),
      high_count=current_severity.get("high", 0),
      medium_count=current_severity.get("medium", 0),
      low_count=current_severity.get("low", 0),
      risk_trend=risk_trend,
      last_incident_at=last_incident.get("detected_at") if last_incident else None,
    )

    return ThreatLevelResponse(
      success=True,
      message="Threat level retrieved successfully",
      data=breakdown,
      generated_at=_utc_now(),
    )

  async def _get_severity_counts(
    self,
    collection,
    match_filter: dict[str, Any],
  ) -> dict[str, int]:
    pipeline = [
      {"$match": match_filter},
      {
        "$group": {
          "_id": {"$toLower": {"$ifNull": ["$severity", "unknown"]}},
          "count": {"$sum": 1},
        }
      },
    ]
    results = await collection.aggregate(pipeline).to_list(length=10)
    return {item["_id"]: item.get("count", 0) for item in results}

  async def get_top_attack_types(self, period_hours: int = 24, limit: int = 10) -> TopAttackTypesResponse:
    threats_collection = get_threat_alerts_collection()
    since = _hours_ago(period_hours)
    match_filter = {"detected_at": {"$gte": since}}

    total_attack_types = await threats_collection.count_documents(match_filter)

    pipeline = [
      {"$match": match_filter},
      {
        "$group": {
          "_id": {"$ifNull": ["$threat_type", "unknown"]},
          "count": {"$sum": 1},
          "severity": {"$max": {"$toLower": {"$ifNull": ["$severity", "unknown"]}}},
          "last_detected_at": {"$max": "$detected_at"},
        }
      },
      {"$sort": {"count": -1}},
      {"$limit": limit},
    ]
    results = await threats_collection.aggregate(pipeline).to_list(length=limit)

    top_attack_types = []
    for item in results:
      count = item.get("count", 0)
      percentage = round((count / total_attack_types) * 100, 2) if total_attack_types > 0 else 0.0
      top_attack_types.append(
        AttackTypeItem(
          threat_type=str(item.get("_id", "unknown")),
          count=count,
          percentage=percentage,
          severity=str(item.get("severity", "unknown")),
          last_detected_at=item.get("last_detected_at"),
        )
      )

    return TopAttackTypesResponse(
      success=True,
      message="Top attack types retrieved successfully",
      total_attack_types=total_attack_types,
      top_attack_types=top_attack_types,
      period_hours=period_hours,
      generated_at=_utc_now(),
    )

  async def get_recent_threat_alerts(
    self,
    period_hours: int = 24,
    limit: int = 10,
    upload_id: Optional[str] = None,
  ) -> list[ThreatAlertItem]:
    threats_collection = get_threat_alerts_collection()
    since = _hours_ago(period_hours)
    match_filter: dict[str, Any] = {"detected_at": {"$gte": since}}

    if upload_id:
      match_filter["metadata.upload_id"] = upload_id

    cursor = threats_collection.find(match_filter).sort("detected_at", -1).limit(limit)
    documents = await cursor.to_list(length=limit)

    recent_alerts: list[ThreatAlertItem] = []
    for document in documents:
      metadata = document.get("metadata") or {}
      recent_alerts.append(
        ThreatAlertItem(
          alert_id=str(document.get("alert_id", "")),
          threat_type=str(document.get("threat_type", "unknown")),
          severity=str(document.get("severity", "low")),
          status=str(document.get("status", "open")),
          source_ip=document.get("source_ip"),
          destination_ip=document.get("destination_ip"),
          flow_id=document.get("flow_id"),
          confidence=document.get("confidence"),
          detected_at=document.get("detected_at", _utc_now()),
          upload_id=metadata.get("upload_id"),
          original_filename=metadata.get("original_filename"),
          analysis_source=metadata.get("analysis_source"),
        )
      )

    return recent_alerts

  async def _get_firewall_rule_counts(self) -> tuple[int, int]:
    rules_collection = get_firewall_rules_collection()
    total_rules = await rules_collection.count_documents({})
    active_rules = await rules_collection.count_documents({"is_enabled": True})
    return active_rules, total_rules

  async def _get_device_counts(self) -> tuple[int, int]:
    devices_collection = get_devices_collection()
    total_devices = await devices_collection.count_documents({})
    trusted_devices = await devices_collection.count_documents({"is_trusted": True})
    return trusted_devices, total_devices

  async def _build_kpis(
    self,
    traffic_summary: TrafficSummaryResponse,
    attack_count: AttackCountBreakdown,
    threat_level: ThreatLevelBreakdown,
  ) -> list[DashboardKPI]:
    return [
      DashboardKPI(
        label="Total Network Flows",
        value=traffic_summary.total_flows,
        unit="flows",
        trend="stable",
      ),
      DashboardKPI(
        label="Total Traffic",
        value=traffic_summary.total_bytes,
        unit="bytes",
        trend="stable",
      ),
      DashboardKPI(
        label="Blocked Flows",
        value=traffic_summary.blocked_flows,
        unit="flows",
        trend="stable",
      ),
      DashboardKPI(
        label="Total Attacks",
        value=attack_count.total_attacks,
        unit="attacks",
        trend=threat_level.risk_trend,
      ),
      DashboardKPI(
        label="Active Alerts",
        value=attack_count.active_alerts,
        unit="alerts",
        trend=threat_level.risk_trend,
      ),
      DashboardKPI(
        label="Threat Score",
        value=threat_level.overall_score,
        unit="score",
        trend=threat_level.risk_trend,
      ),
      DashboardKPI(
        label="Threat Level",
        value=threat_level.overall_level,
        trend=threat_level.risk_trend,
      ),
      DashboardKPI(
        label="Attacks Today",
        value=attack_count.attacks_today,
        unit="attacks",
        trend=threat_level.risk_trend,
      ),
    ]

  async def get_statistics(self, period_hours: int = 24, top_limit: int = 10) -> DashboardStatisticsResponse:
    traffic_summary = await self.get_traffic_summary(period_hours=period_hours)
    attack_count_response = await self.get_attack_count()
    threat_level_response = await self.get_threat_level(period_hours=period_hours)
    top_attack_types_response = await self.get_top_attack_types(
      period_hours=period_hours,
      limit=top_limit,
    )
    recent_threat_alerts = await self.get_recent_threat_alerts(
      period_hours=period_hours,
      limit=top_limit,
    )

    active_rules, total_rules = await self._get_firewall_rule_counts()
    trusted_devices, total_devices = await self._get_device_counts()

    kpis = await self._build_kpis(
      traffic_summary=traffic_summary,
      attack_count=attack_count_response.data,
      threat_level=threat_level_response.data,
    )

    statistics_data = DashboardStatisticsData(
      traffic_summary=traffic_summary,
      attack_count=attack_count_response.data,
      threat_level=threat_level_response.data,
      top_attack_types=top_attack_types_response.top_attack_types,
      recent_threat_alerts=recent_threat_alerts,
      kpis=kpis,
      firewall_rules_active=active_rules,
      firewall_rules_total=total_rules,
      trusted_devices=trusted_devices,
      total_devices=total_devices,
      zero_trust_enabled=settings.zero_trust_enabled,
    )

    return DashboardStatisticsResponse(
      success=True,
      message="Dashboard statistics retrieved successfully",
      data=statistics_data,
      generated_at=_utc_now(),
    )


dashboard_service = DashboardService()
