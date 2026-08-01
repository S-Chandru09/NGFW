from typing import Optional

from fastapi import APIRouter, Depends, Query

from core.auth_utils import require_permission
from models.trust_score import TrustLevel
from models.user import UserPublic
from schemas.trust_score import (
  BehaviourEventCreateRequest,
  BehaviourEventCreateResponse,
  BehaviourEventListResponse,
  TrustScoreCalculateRequest,
  TrustScoreCalculateResponse,
  TrustScoreDetailResponse,
  TrustScoreFilterParams,
  TrustScoreHistoryResponse,
  TrustScoreListResponse,
  TrustScoreStatsResponse,
  TrustScoreStoreRequest,
  TrustScoreStoreResponse,
)
from services.trust_score_service import trust_score_service

router = APIRouter(prefix="/trust-scores", tags=["Trust Scores"])


@router.get(
  "",
  response_model=TrustScoreListResponse,
  summary="Retrieve stored trust scores from MongoDB",
)
async def list_trust_scores(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  user_id: Optional[str] = Query(default=None),
  device_id: Optional[str] = Query(default=None),
  trust_level: Optional[TrustLevel] = Query(default=None),
  is_access_allowed: Optional[bool] = Query(default=None),
  min_composite_score: Optional[float] = Query(default=None, ge=0.0, le=100.0),
  max_composite_score: Optional[float] = Query(default=None, ge=0.0, le=100.0),
  sort_by: str = Query(default="composite_score"),
  sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
  current_user: UserPublic = Depends(require_permission("trust:read")),
) -> TrustScoreListResponse:
  filters = TrustScoreFilterParams(
    user_id=user_id,
    device_id=device_id,
    trust_level=trust_level,
    is_access_allowed=is_access_allowed,
    min_composite_score=min_composite_score,
    max_composite_score=max_composite_score,
  )

  return await trust_score_service.list_trust_scores(
    page=page,
    page_size=page_size,
    filters=filters,
    sort_by=sort_by,
    sort_order=sort_order,
  )


@router.post(
  "",
  response_model=TrustScoreStoreResponse,
  status_code=201,
  summary="Store device, user, and behaviour trust scores in MongoDB",
)
async def store_trust_score(
  store_data: TrustScoreStoreRequest,
  current_user: UserPublic = Depends(require_permission("trust:write")),
) -> TrustScoreStoreResponse:
  return await trust_score_service.store_trust_score(store_data)


@router.get(
  "/stats",
  response_model=TrustScoreStatsResponse,
  summary="Get trust score statistics and component summaries",
)
async def get_trust_score_stats(
  current_user: UserPublic = Depends(require_permission("trust:read")),
) -> TrustScoreStatsResponse:
  return await trust_score_service.get_stats()


@router.get(
  "/history",
  response_model=TrustScoreHistoryResponse,
  summary="Retrieve trust score history for a user or user-device pair from MongoDB",
)
async def get_trust_score_history(
  user_id: str = Query(..., min_length=1),
  device_id: Optional[str] = Query(default=None),
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  current_user: UserPublic = Depends(require_permission("trust:read")),
) -> TrustScoreHistoryResponse:
  return await trust_score_service.get_trust_score_history(
    user_id=user_id,
    device_id=device_id,
    page=page,
    page_size=page_size,
  )


@router.post(
  "/calculate",
  response_model=TrustScoreCalculateResponse,
  summary="Calculate and store device, user, and behaviour trust scores",
)
async def calculate_trust_score(
  request_data: TrustScoreCalculateRequest,
  current_user: UserPublic = Depends(require_permission("trust:write")),
) -> TrustScoreCalculateResponse:
  return await trust_score_service.calculate_trust_score(
    user_id=request_data.user_id,
    device_id=request_data.device_id,
    persist=request_data.persist,
  )


@router.post(
  "/behaviour-events",
  response_model=BehaviourEventCreateResponse,
  status_code=201,
  summary="Record a user behaviour event for trust scoring",
)
async def record_behaviour_event(
  event_data: BehaviourEventCreateRequest,
  current_user: UserPublic = Depends(require_permission("trust:write")),
) -> BehaviourEventCreateResponse:
  return await trust_score_service.record_behaviour_event(event_data)


@router.get(
  "/behaviour-events",
  response_model=BehaviourEventListResponse,
  summary="List behaviour events used for trust scoring",
)
async def list_behaviour_events(
  user_id: Optional[str] = Query(default=None),
  device_id: Optional[str] = Query(default=None),
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=20, ge=1, le=100),
  current_user: UserPublic = Depends(require_permission("trust:read")),
) -> BehaviourEventListResponse:
  return await trust_score_service.list_behaviour_events(
    user_id=user_id,
    device_id=device_id,
    page=page,
    page_size=page_size,
  )


@router.get(
  "/device/{device_id}",
  response_model=TrustScoreCalculateResponse,
  summary="Calculate and retrieve trust score for a device",
)
async def get_device_trust_score(
  device_id: str,
  current_user: UserPublic = Depends(require_permission("trust:read")),
) -> TrustScoreCalculateResponse:
  return await trust_score_service.get_device_score(device_id)


@router.get(
  "/user/{user_id}",
  response_model=TrustScoreDetailResponse,
  summary="Retrieve stored trust score for a user from MongoDB",
)
async def get_user_trust_score(
  user_id: str,
  device_id: Optional[str] = Query(default=None),
  current_user: UserPublic = Depends(require_permission("trust:read")),
) -> TrustScoreDetailResponse:
  return await trust_score_service.get_trust_score(user_id=user_id, device_id=device_id)


@router.get(
  "/user/{user_id}/device/{device_id}",
  response_model=TrustScoreDetailResponse,
  summary="Retrieve stored combined user and device trust score from MongoDB",
)
async def get_user_device_trust_score(
  user_id: str,
  device_id: str,
  current_user: UserPublic = Depends(require_permission("trust:read")),
) -> TrustScoreDetailResponse:
  return await trust_score_service.get_trust_score(user_id=user_id, device_id=device_id)


@router.get(
  "/{score_id}",
  response_model=TrustScoreDetailResponse,
  summary="Retrieve a stored trust score by score_id from MongoDB",
)
async def get_trust_score_by_id(
  score_id: str,
  current_user: UserPublic = Depends(require_permission("trust:read")),
) -> TrustScoreDetailResponse:
  return await trust_score_service.get_trust_score_by_id(score_id)
