from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel, Field


class AnalyticsTotals(BaseModel):
  flow_count: int = 0
  total_bytes: int = 0
  total_packets: int = 0
  threat_count: int = 0
  blocked_count: int = 0
  allowed_count: int = 0
  unique_source_ips: int = 0


class AnalyticsTimePoint(BaseModel):
  period: str
  flow_count: int = 0
  total_bytes: int = 0
  total_packets: int = 0
  threat_count: int = 0
  blocked_count: int = 0
  allowed_count: int = 0
  unique_source_ips: int = 0


class DailyAnalyticsResponse(BaseModel):
  success: bool = True
  message: str
  days: int
  start_date: date
  end_date: date
  data_points: list[AnalyticsTimePoint]
  totals: AnalyticsTotals
  generated_at: datetime


class MonthlyAnalyticsResponse(BaseModel):
  success: bool = True
  message: str
  months: int
  start_period: str
  end_period: str
  data_points: list[AnalyticsTimePoint]
  totals: AnalyticsTotals
  generated_at: datetime


class ProtocolAnalyticsItem(BaseModel):
  protocol: str
  flow_count: int
  total_bytes: int
  total_packets: int
  threat_count: int
  blocked_count: int
  percentage: float


class ProtocolAnalyticsResponse(BaseModel):
  success: bool = True
  message: str
  period_hours: int
  total_flows: int
  total_bytes: int
  protocols: list[ProtocolAnalyticsItem]
  generated_at: datetime


class CountryAnalyticsItem(BaseModel):
  country_code: str
  country_name: str
  flow_count: int
  total_bytes: int
  threat_count: int
  blocked_count: int
  percentage: float
  top_source_ips: list[str] = Field(default_factory=list)


class CountryAnalyticsResponse(BaseModel):
  success: bool = True
  message: str
  period_hours: int
  total_flows: int
  total_bytes: int
  countries: list[CountryAnalyticsItem]
  unknown_flow_count: int = 0
  generated_at: datetime


class AnalyticsOverviewResponse(BaseModel):
  success: bool = True
  message: str
  daily: DailyAnalyticsResponse
  monthly: MonthlyAnalyticsResponse
  protocols: ProtocolAnalyticsResponse
  countries: CountryAnalyticsResponse
  generated_at: datetime
