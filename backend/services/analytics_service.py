from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

from database import get_network_flows_collection, get_threat_alerts_collection
from schemas.analytics import (
  AnalyticsTimePoint,
  AnalyticsTotals,
  CountryAnalyticsItem,
  CountryAnalyticsResponse,
  DailyAnalyticsResponse,
  MonthlyAnalyticsResponse,
  ProtocolAnalyticsItem,
  ProtocolAnalyticsResponse,
)
from services.country_simulation import get_country_name, resolve_country_from_ip


def _utc_now() -> datetime:
  return datetime.now(timezone.utc)


def _build_totals_from_points(points: list[AnalyticsTimePoint]) -> AnalyticsTotals:
  return AnalyticsTotals(
    flow_count=sum(point.flow_count for point in points),
    total_bytes=sum(point.total_bytes for point in points),
    total_packets=sum(point.total_packets for point in points),
    threat_count=sum(point.threat_count for point in points),
    blocked_count=sum(point.blocked_count for point in points),
    allowed_count=sum(point.allowed_count for point in points),
    unique_source_ips=0,
  )


class AnalyticsService:
  def _flow_match_filter(self, since: datetime) -> dict[str, Any]:
    return {"captured_at": {"$gte": since}}

  async def _aggregate_flows_by_period(
    self,
    since: datetime,
    date_format: str,
  ) -> dict[str, dict[str, int]]:
    flows_collection = get_network_flows_collection()

    pipeline = [
      {"$match": self._flow_match_filter(since)},
      {
        "$group": {
          "_id": {
            "$dateToString": {
              "format": date_format,
              "date": "$captured_at",
            }
          },
          "flow_count": {"$sum": 1},
          "total_bytes": {"$sum": {"$ifNull": ["$total_bytes", 0]}},
          "total_packets": {"$sum": {"$ifNull": ["$packet_count", {"$ifNull": ["$total_packets", 0]}]}},
          "threat_count": {
            "$sum": {
              "$cond": [{"$eq": ["$is_threat", True]}, 1, 0],
            },
          },
          "blocked_count": {
            "$sum": {
              "$cond": [{"$eq": ["$action", "block"]}, 1, 0],
            },
          },
          "source_ips": {"$addToSet": "$source_ip"},
        }
      },
      {"$sort": {"_id": 1}},
    ]

    results = await flows_collection.aggregate(pipeline).to_list(length=500)
    period_map: dict[str, dict[str, int]] = {}

    for item in results:
      period_key = str(item.get("_id"))
      blocked_count = int(item.get("blocked_count", 0) or 0)
      flow_count = int(item.get("flow_count", 0) or 0)

      period_map[period_key] = {
        "flow_count": flow_count,
        "total_bytes": int(item.get("total_bytes", 0) or 0),
        "total_packets": int(item.get("total_packets", 0) or 0),
        "threat_count": int(item.get("threat_count", 0) or 0),
        "blocked_count": blocked_count,
        "allowed_count": max(flow_count - blocked_count, 0),
        "unique_source_ips": len(item.get("source_ips", []) or []),
      }

    return period_map

  async def _aggregate_threats_by_period(
    self,
    since: datetime,
    date_format: str,
  ) -> dict[str, int]:
    threats_collection = get_threat_alerts_collection()

    pipeline = [
      {"$match": {"detected_at": {"$gte": since}}},
      {
        "$group": {
          "_id": {
            "$dateToString": {
              "format": date_format,
              "date": "$detected_at",
            }
          },
          "threat_count": {"$sum": 1},
        }
      },
    ]

    results = await threats_collection.aggregate(pipeline).to_list(length=500)
    return {str(item["_id"]): int(item.get("threat_count", 0) or 0) for item in results}

  def _merge_period_point(
    self,
    period_key: str,
    flow_data: Optional[dict[str, int]],
    alert_threat_count: int,
  ) -> AnalyticsTimePoint:
    flow_data = flow_data or {}

    threat_count = max(
      int(flow_data.get("threat_count", 0) or 0),
      alert_threat_count,
    )

    return AnalyticsTimePoint(
      period=period_key,
      flow_count=int(flow_data.get("flow_count", 0) or 0),
      total_bytes=int(flow_data.get("total_bytes", 0) or 0),
      total_packets=int(flow_data.get("total_packets", 0) or 0),
      threat_count=threat_count,
      blocked_count=int(flow_data.get("blocked_count", 0) or 0),
      allowed_count=int(flow_data.get("allowed_count", 0) or 0),
      unique_source_ips=int(flow_data.get("unique_source_ips", 0) or 0),
    )

  async def get_daily_analytics(self, days: int = 30) -> DailyAnalyticsResponse:
    end_date = _utc_now().date()
    start_date = end_date - timedelta(days=days - 1)
    since = datetime.combine(start_date, datetime.min.time(), tzinfo=timezone.utc)

    flow_map = await self._aggregate_flows_by_period(since, "%Y-%m-%d")
    threat_map = await self._aggregate_threats_by_period(since, "%Y-%m-%d")

    data_points: list[AnalyticsTimePoint] = []
    current_date = start_date

    while current_date <= end_date:
      period_key = current_date.isoformat()
      data_points.append(
        self._merge_period_point(
          period_key,
          flow_map.get(period_key),
          threat_map.get(period_key, 0),
        )
      )
      current_date += timedelta(days=1)

    totals = _build_totals_from_points(data_points)

    return DailyAnalyticsResponse(
      success=True,
      message="Daily analytics retrieved successfully",
      days=days,
      start_date=start_date,
      end_date=end_date,
      data_points=data_points,
      totals=totals,
      generated_at=_utc_now(),
    )

  async def get_monthly_analytics(self, months: int = 12) -> MonthlyAnalyticsResponse:
    now = _utc_now()
    end_period = now.strftime("%Y-%m")

    period_keys: list[str] = []
    year = now.year
    month = now.month

    for _ in range(months):
      period_keys.append(f"{year:04d}-{month:02d}")
      month -= 1
      if month == 0:
        month = 12
        year -= 1

    period_keys.reverse()
    start_period = period_keys[0]

    start_year, start_month = map(int, start_period.split("-"))
    since = datetime(start_year, start_month, 1, tzinfo=timezone.utc)

    flow_map = await self._aggregate_flows_by_period(since, "%Y-%m")
    threat_map = await self._aggregate_threats_by_period(since, "%Y-%m")

    data_points = [
      self._merge_period_point(
        period_key,
        flow_map.get(period_key),
        threat_map.get(period_key, 0),
      )
      for period_key in period_keys
    ]

    totals = _build_totals_from_points(data_points)

    return MonthlyAnalyticsResponse(
      success=True,
      message="Monthly analytics retrieved successfully",
      months=months,
      start_period=start_period,
      end_period=end_period,
      data_points=data_points,
      totals=totals,
      generated_at=_utc_now(),
    )

  async def get_protocol_analytics(self, period_hours: int = 24) -> ProtocolAnalyticsResponse:
    flows_collection = get_network_flows_collection()
    since = _utc_now() - timedelta(hours=period_hours)
    match_filter = self._flow_match_filter(since)

    total_flows = await flows_collection.count_documents(match_filter)

    pipeline = [
      {"$match": match_filter},
      {
        "$group": {
          "_id": {"$toUpper": {"$ifNull": ["$protocol", "UNKNOWN"]}},
          "flow_count": {"$sum": 1},
          "total_bytes": {"$sum": {"$ifNull": ["$total_bytes", 0]}},
          "total_packets": {"$sum": {"$ifNull": ["$packet_count", {"$ifNull": ["$total_packets", 0]}]}},
          "threat_count": {
            "$sum": {
              "$cond": [{"$eq": ["$is_threat", True]}, 1, 0],
            },
          },
          "blocked_count": {
            "$sum": {
              "$cond": [{"$eq": ["$action", "block"]}, 1, 0],
            },
          },
        }
      },
      {"$sort": {"flow_count": -1}},
    ]

    results = await flows_collection.aggregate(pipeline).to_list(length=50)
    total_bytes = sum(int(item.get("total_bytes", 0) or 0) for item in results)

    protocols: list[ProtocolAnalyticsItem] = []
    for item in results:
      bytes_count = int(item.get("total_bytes", 0) or 0)
      flow_count = int(item.get("flow_count", 0) or 0)
      percentage = round((bytes_count / total_bytes) * 100, 2) if total_bytes > 0 else 0.0

      protocols.append(
        ProtocolAnalyticsItem(
          protocol=str(item.get("_id", "UNKNOWN")),
          flow_count=flow_count,
          total_bytes=bytes_count,
          total_packets=int(item.get("total_packets", 0) or 0),
          threat_count=int(item.get("threat_count", 0) or 0),
          blocked_count=int(item.get("blocked_count", 0) or 0),
          percentage=percentage,
        )
      )

    return ProtocolAnalyticsResponse(
      success=True,
      message="Protocol analytics retrieved successfully",
      period_hours=period_hours,
      total_flows=total_flows,
      total_bytes=total_bytes,
      protocols=protocols,
      generated_at=_utc_now(),
    )

  async def get_country_analytics(
    self,
    period_hours: int = 24,
    limit: int = 20,
  ) -> CountryAnalyticsResponse:
    flows_collection = get_network_flows_collection()
    since = _utc_now() - timedelta(hours=period_hours)
    match_filter = self._flow_match_filter(since)

    total_flows = await flows_collection.count_documents(match_filter)

    stored_country_pipeline = [
      {"$match": {**match_filter, "source_country": {"$exists": True, "$ne": None}}},
      {
        "$group": {
          "_id": {"$toUpper": "$source_country"},
          "flow_count": {"$sum": 1},
          "total_bytes": {"$sum": {"$ifNull": ["$total_bytes", 0]}},
          "threat_count": {
            "$sum": {
              "$cond": [{"$eq": ["$is_threat", True]}, 1, 0],
            },
          },
          "blocked_count": {
            "$sum": {
              "$cond": [{"$eq": ["$action", "block"]}, 1, 0],
            },
          },
          "source_ips": {"$addToSet": "$source_ip"},
        }
      },
    ]

    stored_results = await flows_collection.aggregate(stored_country_pipeline).to_list(length=limit)

    ip_pipeline = [
      {"$match": match_filter},
      {
        "$group": {
          "_id": {"$ifNull": ["$source_ip", "unknown"]},
          "flow_count": {"$sum": 1},
          "total_bytes": {"$sum": {"$ifNull": ["$total_bytes", 0]}},
          "threat_count": {
            "$sum": {
              "$cond": [{"$eq": ["$is_threat", True]}, 1, 0],
            },
          },
          "blocked_count": {
            "$sum": {
              "$cond": [{"$eq": ["$action", "block"]}, 1, 0],
            },
          },
        }
      },
      {"$sort": {"flow_count": -1}},
      {"$limit": 500},
    ]

    ip_results = await flows_collection.aggregate(ip_pipeline).to_list(length=500)

    country_buckets: dict[str, dict[str, Any]] = defaultdict(
      lambda: {
        "flow_count": 0,
        "total_bytes": 0,
        "threat_count": 0,
        "blocked_count": 0,
        "source_ips": set(),
      }
    )

    for item in stored_results:
      country_code = str(item.get("_id", "UNKNOWN"))
      bucket = country_buckets[country_code]
      bucket["flow_count"] += int(item.get("flow_count", 0) or 0)
      bucket["total_bytes"] += int(item.get("total_bytes", 0) or 0)
      bucket["threat_count"] += int(item.get("threat_count", 0) or 0)
      bucket["blocked_count"] += int(item.get("blocked_count", 0) or 0)
      bucket["source_ips"].update(item.get("source_ips", []) or [])

    unknown_flow_count = 0

    for item in ip_results:
      source_ip = str(item.get("_id", "unknown"))
      country_code = resolve_country_from_ip(source_ip)

      flow_count = int(item.get("flow_count", 0) or 0)
      total_bytes = int(item.get("total_bytes", 0) or 0)
      threat_count = int(item.get("threat_count", 0) or 0)
      blocked_count = int(item.get("blocked_count", 0) or 0)

      if country_code is None:
        unknown_flow_count += flow_count
        continue

      bucket = country_buckets[country_code]
      bucket["flow_count"] += flow_count
      bucket["total_bytes"] += total_bytes
      bucket["threat_count"] += threat_count
      bucket["blocked_count"] += blocked_count
      bucket["source_ips"].add(source_ip)

    total_bytes = sum(int(bucket["total_bytes"]) for bucket in country_buckets.values())

    countries: list[CountryAnalyticsItem] = []
    for country_code, bucket in sorted(
      country_buckets.items(),
      key=lambda item: int(item[1]["flow_count"]),
      reverse=True,
    )[:limit]:
      bytes_count = int(bucket["total_bytes"])
      flow_count = int(bucket["flow_count"])
      percentage = round((bytes_count / total_bytes) * 100, 2) if total_bytes > 0 else 0.0
      country_name = get_country_name(country_code) or country_code

      countries.append(
        CountryAnalyticsItem(
          country_code=country_code,
          country_name=country_name,
          flow_count=flow_count,
          total_bytes=bytes_count,
          threat_count=int(bucket["threat_count"]),
          blocked_count=int(bucket["blocked_count"]),
          percentage=percentage,
          top_source_ips=sorted(bucket["source_ips"])[:5],
        )
      )

    return CountryAnalyticsResponse(
      success=True,
      message="Country analytics retrieved successfully",
      period_hours=period_hours,
      total_flows=total_flows,
      total_bytes=total_bytes,
      countries=countries,
      unknown_flow_count=unknown_flow_count,
      generated_at=_utc_now(),
    )

  async def get_overview(
    self,
    days: int = 30,
    months: int = 12,
    period_hours: int = 24,
  ):
    from schemas.analytics import AnalyticsOverviewResponse

    daily = await self.get_daily_analytics(days=days)
    monthly = await self.get_monthly_analytics(months=months)
    protocols = await self.get_protocol_analytics(period_hours=period_hours)
    countries = await self.get_country_analytics(period_hours=period_hours)

    return AnalyticsOverviewResponse(
      success=True,
      message="Analytics overview retrieved successfully",
      daily=daily,
      monthly=monthly,
      protocols=protocols,
      countries=countries,
      generated_at=_utc_now(),
    )


analytics_service = AnalyticsService()
