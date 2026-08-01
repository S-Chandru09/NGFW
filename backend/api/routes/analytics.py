from fastapi import APIRouter, Depends, Query

from core.auth_utils import require_permission
from models.user import UserPublic
from schemas.analytics import (
  AnalyticsOverviewResponse,
  CountryAnalyticsResponse,
  DailyAnalyticsResponse,
  MonthlyAnalyticsResponse,
  ProtocolAnalyticsResponse,
)
from services.analytics_service import analytics_service

router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get(
  "/daily",
  response_model=DailyAnalyticsResponse,
  summary="Get daily network and threat analytics",
)
async def get_daily_analytics(
  days: int = Query(default=30, ge=1, le=90, description="Number of days to include"),
  current_user: UserPublic = Depends(require_permission("dashboard:read")),
) -> DailyAnalyticsResponse:
  return await analytics_service.get_daily_analytics(days=days)


@router.get(
  "/monthly",
  response_model=MonthlyAnalyticsResponse,
  summary="Get monthly network and threat analytics",
)
async def get_monthly_analytics(
  months: int = Query(default=12, ge=1, le=24, description="Number of months to include"),
  current_user: UserPublic = Depends(require_permission("dashboard:read")),
) -> MonthlyAnalyticsResponse:
  return await analytics_service.get_monthly_analytics(months=months)


@router.get(
  "/protocols",
  response_model=ProtocolAnalyticsResponse,
  summary="Get traffic analytics grouped by protocol",
)
async def get_protocol_analytics(
  period_hours: int = Query(default=24, ge=1, le=168, description="Lookback period in hours"),
  current_user: UserPublic = Depends(require_permission("dashboard:read")),
) -> ProtocolAnalyticsResponse:
  return await analytics_service.get_protocol_analytics(period_hours=period_hours)


@router.get(
  "/countries",
  response_model=CountryAnalyticsResponse,
  summary="Get traffic analytics grouped by source country",
)
async def get_country_analytics(
  period_hours: int = Query(default=24, ge=1, le=168, description="Lookback period in hours"),
  limit: int = Query(default=20, ge=1, le=50, description="Maximum countries to return"),
  current_user: UserPublic = Depends(require_permission("dashboard:read")),
) -> CountryAnalyticsResponse:
  return await analytics_service.get_country_analytics(
    period_hours=period_hours,
    limit=limit,
  )


@router.get(
  "/overview",
  response_model=AnalyticsOverviewResponse,
  summary="Get combined daily, monthly, protocol, and country analytics",
)
async def get_analytics_overview(
  days: int = Query(default=30, ge=1, le=90),
  months: int = Query(default=12, ge=1, le=24),
  period_hours: int = Query(default=24, ge=1, le=168),
  current_user: UserPublic = Depends(require_permission("dashboard:read")),
) -> AnalyticsOverviewResponse:
  return await analytics_service.get_overview(
    days=days,
    months=months,
    period_hours=period_hours,
  )
