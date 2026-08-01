import math
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from bson import ObjectId
from fastapi import HTTPException, status
from pymongo import ASCENDING, DESCENDING

from config import settings
from database import (
  get_audit_logs_collection,
  get_behaviour_events_collection,
  get_devices_collection,
  get_threat_alerts_collection,
  get_trust_scores_collection,
  get_users_collection,
)
from models.trust_score import (
  BehaviourEventCreate,
  BehaviourEventPublic,
  BehaviourEventType,
  BehaviourRiskLevel,
  ScoreFactor,
  TrustLevel,
  TrustScoreBreakdown,
  TrustScoreDocument,
  TrustScorePublic,
)
from models.user import UserDocument, UserRole
from schemas.log import PaginationMeta
from schemas.trust_score import (
  BehaviourEventCreateResponse,
  BehaviourEventListResponse,
  TrustScoreCalculateResponse,
  TrustScoreComponentSummary,
  TrustScoreDetailResponse,
  TrustScoreFilterParams,
  TrustScoreHistoryResponse,
  TrustScoreListResponse,
  TrustScoreStatsResponse,
  TrustScoreStoreRequest,
  TrustScoreStoreResponse,
)


class TrustScoreService:
  DEVICE_WEIGHT = 0.35
  USER_WEIGHT = 0.35
  BEHAVIOUR_WEIGHT = 0.30

  def _utc_now(self) -> datetime:
    return datetime.now(timezone.utc)

  def _hours_ago(self, hours: int) -> datetime:
    return self._utc_now() - timedelta(hours=hours)

  def _clamp_score(self, score: float) -> float:
    return max(0.0, min(round(score, 2), 100.0))

  def _resolve_trust_level(self, composite_score: float) -> TrustLevel:
    if composite_score >= 85:
      return TrustLevel.VERIFIED
    if composite_score >= 70:
      return TrustLevel.HIGH
    if composite_score >= 50:
      return TrustLevel.MEDIUM
    if composite_score >= 30:
      return TrustLevel.LOW
    return TrustLevel.CRITICAL

  def _build_pagination_meta(self, page: int, page_size: int, total_items: int) -> PaginationMeta:
    total_pages = math.ceil(total_items / page_size) if page_size > 0 else 0

    return PaginationMeta(
      page=page,
      page_size=page_size,
      total_items=total_items,
      total_pages=total_pages,
      has_next=page < total_pages,
      has_previous=page > 1 and total_pages > 0,
    )

  def _get_sort_direction(self, sort_order: str) -> int:
    return ASCENDING if sort_order.lower() == "asc" else DESCENDING

  def _build_filter_query(self, filters: TrustScoreFilterParams) -> dict[str, Any]:
    query: dict[str, Any] = {}

    if filters.user_id is not None:
      query["user_id"] = filters.user_id

    if filters.device_id is not None:
      query["device_id"] = filters.device_id

    if filters.trust_level is not None:
      query["trust_level"] = filters.trust_level.value

    if filters.is_access_allowed is not None:
      query["is_access_allowed"] = filters.is_access_allowed

    if filters.min_composite_score is not None or filters.max_composite_score is not None:
      composite_filter: dict[str, Any] = {}

      if filters.min_composite_score is not None:
        composite_filter["$gte"] = filters.min_composite_score

      if filters.max_composite_score is not None:
        composite_filter["$lte"] = filters.max_composite_score

      query["composite_score"] = composite_filter

    return query

  def _build_breakdown(
    self,
    device_score: float,
    user_score: float,
    behaviour_score: float,
    device_factors: list[ScoreFactor] | None = None,
    user_factors: list[ScoreFactor] | None = None,
    behaviour_factors: list[ScoreFactor] | None = None,
  ) -> TrustScoreBreakdown:
    composite_score = self._clamp_score(
      device_score * self.DEVICE_WEIGHT
      + user_score * self.USER_WEIGHT
      + behaviour_score * self.BEHAVIOUR_WEIGHT
    )

    return TrustScoreBreakdown(
      device_score=self._clamp_score(device_score),
      user_score=self._clamp_score(user_score),
      behaviour_score=self._clamp_score(behaviour_score),
      composite_score=composite_score,
      trust_level=self._resolve_trust_level(composite_score),
      is_access_allowed=composite_score >= settings.min_trust_score_for_access,
      min_required_score=settings.min_trust_score_for_access,
      device_factors=device_factors or [],
      user_factors=user_factors or [],
      behaviour_factors=behaviour_factors or [],
    )

  async def _persist_trust_score(
    self,
    user_id: str,
    breakdown: TrustScoreBreakdown,
    device_id: Optional[str] = None,
    username: Optional[str] = None,
    device_name: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
    store_mode: str = "upsert",
  ) -> TrustScorePublic:
    trust_scores_collection = get_trust_scores_collection()
    score_document = TrustScoreDocument.create_score_document(
      user_id=user_id,
      device_id=device_id,
      username=username,
      device_name=device_name,
      breakdown=breakdown,
      metadata=metadata,
    )

    if store_mode == "upsert":
      existing_document = await trust_scores_collection.find_one(
        {"user_id": user_id, "device_id": device_id}
      )

      if existing_document is not None:
        score_document["score_id"] = existing_document["score_id"]
        score_document["created_at"] = existing_document["created_at"]
        await trust_scores_collection.update_one(
          {"_id": existing_document["_id"]},
          {"$set": score_document},
        )
        saved_document = await trust_scores_collection.find_one({"_id": existing_document["_id"]})
      else:
        insert_result = await trust_scores_collection.insert_one(score_document)
        saved_document = await trust_scores_collection.find_one({"_id": insert_result.inserted_id})
    else:
      insert_result = await trust_scores_collection.insert_one(score_document)
      saved_document = await trust_scores_collection.find_one({"_id": insert_result.inserted_id})

    trust_score_public = TrustScoreDocument.from_mongo(saved_document)

    if trust_score_public is None:
      raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to persist trust score to MongoDB",
      )

    return trust_score_public

  async def _get_user_document(self, user_id: str) -> Optional[dict[str, Any]]:
    users_collection = get_users_collection()

    if ObjectId.is_valid(user_id):
      document = await users_collection.find_one({"_id": ObjectId(user_id)})
      if document is not None:
        return document

    return await users_collection.find_one({"username": user_id.lower()})

  async def _get_device_document(self, device_id: str) -> Optional[dict[str, Any]]:
    devices_collection = get_devices_collection()
    document = await devices_collection.find_one({"device_id": device_id})

    if document is None and ObjectId.is_valid(device_id):
      document = await devices_collection.find_one({"_id": ObjectId(device_id)})

    return document

  async def calculate_device_score(self, device_id: Optional[str] = None) -> tuple[float, list[ScoreFactor]]:
    factors: list[ScoreFactor] = []
    score = settings.default_device_trust_score
    factors.append(
      ScoreFactor(
        factor="base_device_score",
        impact=score,
        description="Default baseline device trust score",
      )
    )

    if device_id is None:
      return self._clamp_score(score), factors

    device_document = await self._get_device_document(device_id)

    if device_document is None:
      factors.append(
        ScoreFactor(
          factor="unknown_device",
          impact=-15.0,
          description="Device not registered in inventory",
        )
      )
      return self._clamp_score(score - 15.0), factors

    if device_document.get("is_trusted"):
      score += 20.0
      factors.append(
        ScoreFactor(
          factor="trusted_device",
          impact=20.0,
          description="Device marked as trusted",
        )
      )

    if device_document.get("is_compliant", True):
      score += 10.0
      factors.append(
        ScoreFactor(
          factor="device_compliance",
          impact=10.0,
          description="Device meets compliance requirements",
        )
      )
    else:
      score -= 20.0
      factors.append(
        ScoreFactor(
          factor="non_compliant_device",
          impact=-20.0,
          description="Device failed compliance checks",
        )
      )

    device_type = device_document.get("device_type", "unknown")
    if device_type in {"laptop", "desktop", "mobile", "tablet"}:
      score += 5.0
      factors.append(
        ScoreFactor(
          factor="known_device_type",
          impact=5.0,
          description=f"Recognized device type: {device_type}",
        )
      )
    elif device_type in {"iot", "unknown"}:
      score -= 10.0
      factors.append(
        ScoreFactor(
          factor="high_risk_device_type",
          impact=-10.0,
          description=f"Higher risk device type: {device_type}",
        )
      )

    last_seen_at = device_document.get("last_seen_at")
    if isinstance(last_seen_at, datetime):
      if last_seen_at.tzinfo is None:
        last_seen_at = last_seen_at.replace(tzinfo=timezone.utc)

      hours_since_seen = (self._utc_now() - last_seen_at).total_seconds() / 3600

      if hours_since_seen <= 24:
        score += 10.0
        factors.append(
          ScoreFactor(
            factor="recent_activity",
            impact=10.0,
            description="Device seen within the last 24 hours",
          )
        )
      elif hours_since_seen > 24 * 30:
        score -= 15.0
        factors.append(
          ScoreFactor(
            factor="stale_device",
            impact=-15.0,
            description="Device inactive for more than 30 days",
          )
        )

    threats_collection = get_threat_alerts_collection()
    threat_count = await threats_collection.count_documents(
      {
        "device_id": device_document.get("device_id"),
        "detected_at": {"$gte": self._hours_ago(24 * 7)},
      }
    )

    if threat_count > 0:
      penalty = min(threat_count * 8.0, 30.0)
      score -= penalty
      factors.append(
        ScoreFactor(
          factor="recent_threats",
          impact=-penalty,
          description=f"{threat_count} threat alert(s) linked to device in last 7 days",
        )
      )

    return self._clamp_score(score), factors

  async def calculate_user_score(self, user_id: str) -> tuple[float, list[ScoreFactor], Optional[dict[str, Any]]]:
    factors: list[ScoreFactor] = []
    score = 50.0
    factors.append(
      ScoreFactor(
        factor="base_user_score",
        impact=50.0,
        description="Default baseline user trust score",
      )
    )

    user_document = await self._get_user_document(user_id)

    if user_document is None:
      factors.append(
        ScoreFactor(
          factor="unknown_user",
          impact=-25.0,
          description="User account not found",
        )
      )
      return self._clamp_score(score - 25.0), factors, None

    user = UserDocument.from_mongo(user_document)

    if user is None:
      return self._clamp_score(score), factors, user_document

    if user.is_active:
      score += 15.0
      factors.append(
        ScoreFactor(
          factor="active_account",
          impact=15.0,
          description="User account is active",
        )
      )
    else:
      score -= 30.0
      factors.append(
        ScoreFactor(
          factor="inactive_account",
          impact=-30.0,
          description="User account is inactive",
        )
      )

    if user.last_login_at:
      last_login = user.last_login_at
      if last_login.tzinfo is None:
        last_login = last_login.replace(tzinfo=timezone.utc)

      days_since_login = (self._utc_now() - last_login).days

      if days_since_login <= 7:
        score += 10.0
        factors.append(
          ScoreFactor(
            factor="recent_login",
            impact=10.0,
            description="User logged in within the last 7 days",
          )
        )
      elif days_since_login > 30:
        score -= 10.0
        factors.append(
          ScoreFactor(
            factor="stale_login",
            impact=-10.0,
            description="No login activity in over 30 days",
          )
        )

    role_bonus = {
      UserRole.VIEWER: 10.0,
      UserRole.ANALYST: 5.0,
      UserRole.ADMIN: 0.0,
    }
    role_impact = role_bonus.get(user.role, 0.0)
    score += role_impact
    factors.append(
      ScoreFactor(
        factor="role_risk_profile",
        impact=role_impact,
        description=f"Role-based risk adjustment for {user.role.value}",
      )
    )

    audit_logs_collection = get_audit_logs_collection()
    since = self._hours_ago(24)
    user_id_str = str(user_document["_id"])

    failed_logins = await audit_logs_collection.count_documents(
      {
        "user_id": user_id_str,
        "event_type": "auth",
        "severity": {"$in": ["warning", "error", "critical"]},
        "created_at": {"$gte": since},
      }
    )

    if failed_logins > 0:
      penalty = min(failed_logins * 5.0, 25.0)
      score -= penalty
      factors.append(
        ScoreFactor(
          factor="failed_auth_attempts",
          impact=-penalty,
          description=f"{failed_logins} failed authentication event(s) in last 24 hours",
        )
      )
    else:
      score += 5.0
      factors.append(
        ScoreFactor(
          factor="clean_auth_history",
          impact=5.0,
          description="No failed authentication attempts in last 24 hours",
        )
      )

    return self._clamp_score(score), factors, user_document

  async def calculate_behaviour_score(
    self,
    user_id: str,
    device_id: Optional[str] = None,
    period_hours: int = 168,
  ) -> tuple[float, list[ScoreFactor]]:
    factors: list[ScoreFactor] = []
    score = 55.0
    factors.append(
      ScoreFactor(
        factor="base_behaviour_score",
        impact=55.0,
        description="Default baseline behaviour trust score",
      )
    )

    behaviour_collection = get_behaviour_events_collection()
    since = self._hours_ago(period_hours)
    query: dict[str, Any] = {"user_id": user_id, "created_at": {"$gte": since}}

    if device_id is not None:
      query["device_id"] = device_id

    events = await behaviour_collection.find(query).sort("created_at", DESCENDING).to_list(length=500)

    if not events:
      factors.append(
        ScoreFactor(
          factor="no_behaviour_data",
          impact=-5.0,
          description="No behaviour events recorded in evaluation window",
        )
      )
      return self._clamp_score(score - 5.0), factors

    risk_penalties = {
      BehaviourRiskLevel.LOW.value: 2.0,
      BehaviourRiskLevel.MEDIUM.value: 6.0,
      BehaviourRiskLevel.HIGH.value: 12.0,
      BehaviourRiskLevel.CRITICAL.value: 20.0,
    }

    suspicious_types = {
      BehaviourEventType.UNUSUAL_LOCATION.value,
      BehaviourEventType.OFF_HOURS_ACCESS.value,
      BehaviourEventType.PRIVILEGE_ESCALATION.value,
      BehaviourEventType.DATA_EXFILTRATION.value,
      BehaviourEventType.POLICY_VIOLATION.value,
      BehaviourEventType.MALWARE_DETECTED.value,
      BehaviourEventType.LOGIN_FAILURE.value,
    }

    penalty_total = 0.0
    bonus_total = 0.0
    suspicious_count = 0
    normal_count = 0

    for event in events:
      event_type = event.get("event_type")
      risk_level = event.get("risk_level", BehaviourRiskLevel.LOW.value)

      if event_type in suspicious_types:
        suspicious_count += 1
        penalty_total += risk_penalties.get(risk_level, 5.0)
      elif event_type in {
        BehaviourEventType.LOGIN_SUCCESS.value,
        BehaviourEventType.LOGOUT.value,
        BehaviourEventType.NORMAL_ACTIVITY.value,
      }:
        normal_count += 1
        bonus_total += 1.5

    if suspicious_count > 0:
      penalty = min(penalty_total, 40.0)
      score -= penalty
      factors.append(
        ScoreFactor(
          factor="suspicious_behaviour",
          impact=-penalty,
          description=f"{suspicious_count} suspicious behaviour event(s) detected",
        )
      )

    if normal_count > 0:
      bonus = min(bonus_total, 15.0)
      score += bonus
      factors.append(
        ScoreFactor(
          factor="verified_behaviour",
          impact=bonus,
          description=f"{normal_count} verified normal behaviour event(s)",
        )
      )

    threats_collection = get_threat_alerts_collection()
    threat_query: dict[str, Any] = {"detected_at": {"$gte": since}}

    if device_id is not None:
      threat_query["device_id"] = device_id
    else:
      threat_query["user_id"] = user_id

    threat_count = await threats_collection.count_documents(threat_query)

    if threat_count > 0:
      penalty = min(threat_count * 10.0, 30.0)
      score -= penalty
      factors.append(
        ScoreFactor(
          factor="threat_correlation",
          impact=-penalty,
          description=f"{threat_count} correlated threat alert(s) in behaviour window",
        )
      )

    return self._clamp_score(score), factors

  async def calculate_trust_score(
    self,
    user_id: str,
    device_id: Optional[str] = None,
    persist: bool = True,
  ) -> TrustScoreCalculateResponse:
    user_document = await self._get_user_document(user_id)

    if user_document is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"User with id '{user_id}' not found",
      )

    resolved_user_id = str(user_document["_id"])
    user = UserDocument.from_mongo(user_document)

    device_document = None
    resolved_device_id = device_id

    if device_id is not None:
      device_document = await self._get_device_document(device_id)
      if device_document is None:
        raise HTTPException(
          status_code=status.HTTP_404_NOT_FOUND,
          detail=f"Device with id '{device_id}' not found",
        )
      resolved_device_id = device_document.get("device_id", device_id)

    device_score, device_factors = await self.calculate_device_score(resolved_device_id)
    user_score, user_factors, _ = await self.calculate_user_score(resolved_user_id)
    behaviour_score, behaviour_factors = await self.calculate_behaviour_score(
      resolved_user_id,
      resolved_device_id,
    )

    breakdown = self._build_breakdown(
      device_score=device_score,
      user_score=user_score,
      behaviour_score=behaviour_score,
      device_factors=device_factors,
      user_factors=user_factors,
      behaviour_factors=behaviour_factors,
    )

    trust_score_public = None

    if persist:
      trust_score_public = await self._persist_trust_score(
        user_id=resolved_user_id,
        device_id=resolved_device_id,
        username=user.username if user else None,
        device_name=device_document.get("device_name") if device_document else None,
        breakdown=breakdown,
        store_mode="upsert",
      )
    else:
      ephemeral_document = TrustScoreDocument.create_score_document(
        user_id=resolved_user_id,
        device_id=resolved_device_id,
        username=user.username if user else None,
        device_name=device_document.get("device_name") if device_document else None,
        breakdown=breakdown,
      )
      ephemeral_document["_id"] = ObjectId()
      trust_score_public = TrustScoreDocument.from_mongo(ephemeral_document)

    if trust_score_public is None:
      raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to calculate trust score",
      )

    if device_document is not None:
      devices_collection = get_devices_collection()
      await devices_collection.update_one(
        {"device_id": resolved_device_id},
        {
          "$set": {
            "trust_score": breakdown.composite_score,
            "is_trusted": breakdown.is_access_allowed,
            "updated_at": self._utc_now(),
          }
        },
      )

    return TrustScoreCalculateResponse(
      message="Trust score calculated successfully",
      trust_score=trust_score_public,
      breakdown=breakdown,
    )

  async def store_trust_score(self, store_data: TrustScoreStoreRequest) -> TrustScoreStoreResponse:
    user_document = await self._get_user_document(store_data.user_id)

    if user_document is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"User with id '{store_data.user_id}' not found",
      )

    resolved_user_id = str(user_document["_id"])
    user = UserDocument.from_mongo(user_document)
    device_document = None
    resolved_device_id = store_data.device_id

    if store_data.device_id is not None:
      device_document = await self._get_device_document(store_data.device_id)
      if device_document is None:
        raise HTTPException(
          status_code=status.HTTP_404_NOT_FOUND,
          detail=f"Device with id '{store_data.device_id}' not found",
        )
      resolved_device_id = device_document.get("device_id", store_data.device_id)

    breakdown = self._build_breakdown(
      device_score=store_data.device_score,
      user_score=store_data.user_score,
      behaviour_score=store_data.behaviour_score,
      device_factors=store_data.device_factors,
      user_factors=store_data.user_factors,
      behaviour_factors=store_data.behaviour_factors,
    )

    trust_score_public = await self._persist_trust_score(
      user_id=resolved_user_id,
      device_id=resolved_device_id,
      username=user.username if user else None,
      device_name=device_document.get("device_name") if device_document else None,
      breakdown=breakdown,
      metadata=store_data.metadata,
      store_mode=store_data.store_mode,
    )

    if device_document is not None:
      devices_collection = get_devices_collection()
      await devices_collection.update_one(
        {"device_id": resolved_device_id},
        {
          "$set": {
            "trust_score": breakdown.composite_score,
            "is_trusted": breakdown.is_access_allowed,
            "updated_at": self._utc_now(),
          }
        },
      )

    return TrustScoreStoreResponse(
      message="Trust score stored successfully in MongoDB",
      trust_score=trust_score_public,
      store_mode=store_data.store_mode,
    )

  async def get_trust_score_by_id(self, score_id: str) -> TrustScoreDetailResponse:
    trust_scores_collection = get_trust_scores_collection()
    document = await trust_scores_collection.find_one({"score_id": score_id})

    if document is None and ObjectId.is_valid(score_id):
      document = await trust_scores_collection.find_one({"_id": ObjectId(score_id)})

    if document is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Trust score with id '{score_id}' not found",
      )

    trust_score = TrustScoreDocument.from_mongo(document)

    if trust_score is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Trust score with id '{score_id}' not found",
      )

    return TrustScoreDetailResponse(
      message="Trust score retrieved successfully from MongoDB",
      trust_score=trust_score,
    )

  async def get_trust_score_history(
    self,
    user_id: str,
    device_id: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
  ) -> TrustScoreHistoryResponse:
    user_document = await self._get_user_document(user_id)

    if user_document is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"User with id '{user_id}' not found",
      )

    resolved_user_id = str(user_document["_id"])
    trust_scores_collection = get_trust_scores_collection()
    query: dict[str, Any] = {"user_id": resolved_user_id}
    resolved_device_id = None

    if device_id is not None:
      device_document = await self._get_device_document(device_id)
      if device_document is None:
        raise HTTPException(
          status_code=status.HTTP_404_NOT_FOUND,
          detail=f"Device with id '{device_id}' not found",
        )
      resolved_device_id = device_document.get("device_id", device_id)
      query["device_id"] = resolved_device_id

    skip = (page - 1) * page_size
    total_items = await trust_scores_collection.count_documents(query)
    documents = await (
      trust_scores_collection.find(query)
      .sort("calculated_at", DESCENDING)
      .skip(skip)
      .limit(page_size)
      .to_list(length=page_size)
    )

    items = [
      trust_score
      for document in documents
      if (trust_score := TrustScoreDocument.from_mongo(document)) is not None
    ]

    return TrustScoreHistoryResponse(
      message="Trust score history retrieved successfully from MongoDB",
      user_id=resolved_user_id,
      device_id=resolved_device_id,
      items=items,
      pagination=self._build_pagination_meta(page, page_size, total_items),
    )

  async def list_trust_scores(
    self,
    page: int = 1,
    page_size: int = 20,
    filters: TrustScoreFilterParams | None = None,
    sort_by: str = "composite_score",
    sort_order: str = "desc",
  ) -> TrustScoreListResponse:
    trust_scores_collection = get_trust_scores_collection()
    filter_query = self._build_filter_query(filters or TrustScoreFilterParams())
    sort_field = sort_by if sort_by in {
      "composite_score",
      "device_score",
      "user_score",
      "behaviour_score",
      "calculated_at",
      "created_at",
    } else "composite_score"
    sort_direction = self._get_sort_direction(sort_order)
    skip = (page - 1) * page_size

    total_items = await trust_scores_collection.count_documents(filter_query)
    cursor = (
      trust_scores_collection.find(filter_query)
      .sort(sort_field, sort_direction)
      .skip(skip)
      .limit(page_size)
    )

    documents = await cursor.to_list(length=page_size)
    items = [
      trust_score
      for document in documents
      if (trust_score := TrustScoreDocument.from_mongo(document)) is not None
    ]

    return TrustScoreListResponse(
      message="Trust scores retrieved successfully",
      items=items,
      pagination=self._build_pagination_meta(page, page_size, total_items),
    )

  async def get_trust_score(
    self,
    user_id: str,
    device_id: Optional[str] = None,
  ) -> TrustScoreDetailResponse:
    user_document = await self._get_user_document(user_id)

    if user_document is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"User with id '{user_id}' not found",
      )

    resolved_user_id = str(user_document["_id"])
    trust_scores_collection = get_trust_scores_collection()
    query: dict[str, Any] = {"user_id": resolved_user_id}

    if device_id is not None:
      device_document = await self._get_device_document(device_id)
      if device_document is None:
        raise HTTPException(
          status_code=status.HTTP_404_NOT_FOUND,
          detail=f"Device with id '{device_id}' not found",
        )
      query["device_id"] = device_document.get("device_id", device_id)

    document = await trust_scores_collection.find_one(query, sort=[("calculated_at", DESCENDING)])

    if document is None:
      result = await self.calculate_trust_score(
        user_id=resolved_user_id,
        device_id=query.get("device_id"),
        persist=True,
      )
      return TrustScoreDetailResponse(
        message="Trust score calculated successfully",
        trust_score=result.trust_score,
      )

    trust_score = TrustScoreDocument.from_mongo(document)

    if trust_score is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Trust score not found",
      )

    return TrustScoreDetailResponse(
      message="Trust score retrieved successfully",
      trust_score=trust_score,
    )

  async def get_device_score(self, device_id: str) -> TrustScoreCalculateResponse:
    device_document = await self._get_device_document(device_id)

    if device_document is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Device with id '{device_id}' not found",
      )

    user_id = device_document.get("user_id")

    if not user_id:
      device_score, device_factors = await self.calculate_device_score(device_id)
      behaviour_score, behaviour_factors = await self.calculate_behaviour_score(
        user_id="unknown",
        device_id=device_document.get("device_id"),
      )

      composite_score = self._clamp_score(
        device_score * 0.5 + behaviour_score * 0.5
      )

      breakdown = TrustScoreBreakdown(
        device_score=device_score,
        user_score=0.0,
        behaviour_score=behaviour_score,
        composite_score=composite_score,
        trust_level=self._resolve_trust_level(composite_score),
        is_access_allowed=composite_score >= settings.min_trust_score_for_access,
        min_required_score=settings.min_trust_score_for_access,
        device_factors=device_factors,
        user_factors=[
          ScoreFactor(
            factor="unassigned_device",
            impact=0.0,
            description="Device not linked to a user account",
          )
        ],
        behaviour_factors=behaviour_factors,
      )

      now = self._utc_now()
      ephemeral_document = TrustScoreDocument.create_score_document(
        user_id="unknown",
        device_id=device_document.get("device_id"),
        device_name=device_document.get("device_name"),
        breakdown=breakdown,
      )
      ephemeral_document["_id"] = ObjectId()
      trust_score_public = TrustScoreDocument.from_mongo(ephemeral_document)

      if trust_score_public is None:
        raise HTTPException(
          status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
          detail="Failed to calculate device trust score",
        )

      return TrustScoreCalculateResponse(
        message="Device trust score calculated successfully",
        trust_score=trust_score_public,
        breakdown=breakdown,
      )

    return await self.calculate_trust_score(user_id=user_id, device_id=device_id, persist=True)

  async def record_behaviour_event(
    self,
    event_data: BehaviourEventCreate,
  ) -> BehaviourEventCreateResponse:
    user_document = await self._get_user_document(event_data.user_id)

    if user_document is None:
      raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"User with id '{event_data.user_id}' not found",
      )

    if event_data.device_id is not None:
      device_document = await self._get_device_document(event_data.device_id)
      if device_document is None:
        raise HTTPException(
          status_code=status.HTTP_404_NOT_FOUND,
          detail=f"Device with id '{event_data.device_id}' not found",
        )

    behaviour_collection = get_behaviour_events_collection()
    event_document = TrustScoreDocument.create_behaviour_event_document(event_data)
    event_document["user_id"] = str(user_document["_id"])

    if event_data.device_id is not None:
      device_document = await self._get_device_document(event_data.device_id)
      event_document["device_id"] = device_document.get("device_id") if device_document else event_data.device_id

    insert_result = await behaviour_collection.insert_one(event_document)
    created_document = await behaviour_collection.find_one({"_id": insert_result.inserted_id})
    event_public = TrustScoreDocument.behaviour_from_mongo(created_document)

    if event_public is None:
      raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to record behaviour event",
      )

    return BehaviourEventCreateResponse(
      message="Behaviour event recorded successfully",
      event=event_public,
    )

  async def list_behaviour_events(
    self,
    user_id: Optional[str] = None,
    device_id: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
  ) -> BehaviourEventListResponse:
    behaviour_collection = get_behaviour_events_collection()
    query: dict[str, Any] = {}

    if user_id is not None:
      user_document = await self._get_user_document(user_id)
      if user_document is not None:
        query["user_id"] = str(user_document["_id"])
      else:
        query["user_id"] = user_id

    if device_id is not None:
      device_document = await self._get_device_document(device_id)
      query["device_id"] = device_document.get("device_id") if device_document else device_id

    skip = (page - 1) * page_size
    total_items = await behaviour_collection.count_documents(query)
    documents = await (
      behaviour_collection.find(query)
      .sort("created_at", DESCENDING)
      .skip(skip)
      .limit(page_size)
      .to_list(length=page_size)
    )

    items = [
      event
      for document in documents
      if (event := TrustScoreDocument.behaviour_from_mongo(document)) is not None
    ]

    return BehaviourEventListResponse(
      message="Behaviour events retrieved successfully",
      items=items,
      pagination=self._build_pagination_meta(page, page_size, total_items),
    )

  async def get_stats(self) -> TrustScoreStatsResponse:
    trust_scores_collection = get_trust_scores_collection()
    documents = await trust_scores_collection.find({}).to_list(length=10000)

    if not documents:
      empty_summary = TrustScoreComponentSummary(
        average_score=0.0,
        min_score=0.0,
        max_score=0.0,
        total_evaluated=0,
      )

      return TrustScoreStatsResponse(
        message="Trust score statistics retrieved successfully",
        total_scores=0,
        access_allowed_count=0,
        access_denied_count=0,
        zero_trust_enabled=settings.zero_trust_enabled,
        min_required_score=settings.min_trust_score_for_access,
        average_composite_score=0.0,
        device_score_summary=empty_summary,
        user_score_summary=empty_summary,
        behaviour_score_summary=empty_summary,
        trust_level_distribution={level.value: 0 for level in TrustLevel},
        calculated_at=self._utc_now(),
      )

    device_scores = [document.get("device_score", 0.0) for document in documents]
    user_scores = [document.get("user_score", 0.0) for document in documents]
    behaviour_scores = [document.get("behaviour_score", 0.0) for document in documents]
    composite_scores = [document.get("composite_score", 0.0) for document in documents]

    trust_level_distribution = {level.value: 0 for level in TrustLevel}
    access_allowed_count = 0

    for document in documents:
      trust_level = document.get("trust_level", TrustLevel.CRITICAL.value)
      trust_level_distribution[trust_level] = trust_level_distribution.get(trust_level, 0) + 1

      if document.get("is_access_allowed"):
        access_allowed_count += 1

    def build_summary(scores: list[float]) -> TrustScoreComponentSummary:
      return TrustScoreComponentSummary(
        average_score=round(sum(scores) / len(scores), 2),
        min_score=round(min(scores), 2),
        max_score=round(max(scores), 2),
        total_evaluated=len(scores),
      )

    return TrustScoreStatsResponse(
      message="Trust score statistics retrieved successfully",
      total_scores=len(documents),
      access_allowed_count=access_allowed_count,
      access_denied_count=len(documents) - access_allowed_count,
      zero_trust_enabled=settings.zero_trust_enabled,
      min_required_score=settings.min_trust_score_for_access,
      average_composite_score=round(sum(composite_scores) / len(composite_scores), 2),
      device_score_summary=build_summary(device_scores),
      user_score_summary=build_summary(user_scores),
      behaviour_score_summary=build_summary(behaviour_scores),
      trust_level_distribution=trust_level_distribution,
      calculated_at=self._utc_now(),
    )


trust_score_service = TrustScoreService()
