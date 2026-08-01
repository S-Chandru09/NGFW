from fastapi import APIRouter, Depends, Query
from typing import Optional

from core.auth_utils import require_permission
from models.user import UserPublic
from schemas.dashboard import (
  AttackCountResponse,
  DashboardStatisticsResponse,
  ThreatAlertItem,
  ThreatLevelResponse,
  TopAttackTypesResponse,
  TrafficSummaryResponse,
)
from services.dashboard_service import dashboard_service

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get(
  "/traffic-summary",
  response_model=TrafficSummaryResponse,
  summary="Get network traffic summary",
)
async def get_traffic_summary(
  period_hours: int = Query(default=24, ge=1, le=168),
  current_user: UserPublic = Depends(require_permission("dashboard:read")),
) -> TrafficSummaryResponse:
  return await dashboard_service.get_traffic_summary(period_hours=period_hours)


@router.get(
  "/attack-count",
  response_model=AttackCountResponse,
  summary="Get attack count statistics",
)
async def get_attack_count(
  current_user: UserPublic = Depends(require_permission("dashboard:read")),
) -> AttackCountResponse:
  return await dashboard_service.get_attack_count()


@router.get(
  "/threat-level",
  response_model=ThreatLevelResponse,
  summary="Get current threat level assessment",
)
async def get_threat_level(
  period_hours: int = Query(default=24, ge=1, le=168),
  current_user: UserPublic = Depends(require_permission("dashboard:read")),
) -> ThreatLevelResponse:
  return await dashboard_service.get_threat_level(period_hours=period_hours)


@router.get(
  "/top-attack-types",
  response_model=TopAttackTypesResponse,
  summary="Get top attack types by frequency",
)
async def get_top_attack_types(
  period_hours: int = Query(default=24, ge=1, le=168),
  limit: int = Query(default=10, ge=1, le=50),
  current_user: UserPublic = Depends(require_permission("dashboard:read")),
) -> TopAttackTypesResponse:
  return await dashboard_service.get_top_attack_types(
    period_hours=period_hours,
    limit=limit,
  )


@router.get(
  "/statistics",
  response_model=DashboardStatisticsResponse,
  summary="Get complete dashboard statistics",
)
async def get_dashboard_statistics(
  period_hours: int = Query(default=24, ge=1, le=168),
  top_limit: int = Query(default=10, ge=1, le=50),
  current_user: UserPublic = Depends(require_permission("dashboard:read")),
) -> DashboardStatisticsResponse:
  return await dashboard_service.get_statistics(
    period_hours=period_hours,
    top_limit=top_limit,
  )


@router.get(
  "/threat-alerts",
  response_model=list[ThreatAlertItem],
  summary="Get recent threat alerts",
)
async def get_recent_threat_alerts(
  period_hours: int = Query(default=24, ge=1, le=168),
  limit: int = Query(default=10, ge=1, le=100),
  upload_id: Optional[str] = Query(default=None),
  current_user: UserPublic = Depends(require_permission("dashboard:read")),
) -> list[ThreatAlertItem]:
  return await dashboard_service.get_recent_threat_alerts(
    period_hours=period_hours,
    limit=limit,
    upload_id=upload_id,
  )
