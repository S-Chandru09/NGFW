from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator

from models.trust_score import (
  BehaviourEventCreate,
  BehaviourEventPublic,
  ScoreFactor,
  TrustLevel,
  TrustScoreBreakdown,
  TrustScorePublic,
)
from schemas.log import PaginationMeta


class TrustScoreFilterParams(BaseModel):
  user_id: Optional[str] = None
  device_id: Optional[str] = None
  trust_level: Optional[TrustLevel] = None
  is_access_allowed: Optional[bool] = None
  min_composite_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
  max_composite_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)


class TrustScoreStoreRequest(BaseModel):
  user_id: str
  device_id: Optional[str] = None
  device_score: float = Field(..., ge=0.0, le=100.0)
  user_score: float = Field(..., ge=0.0, le=100.0)
  behaviour_score: float = Field(..., ge=0.0, le=100.0)
  device_factors: list[ScoreFactor] = Field(default_factory=list)
  user_factors: list[ScoreFactor] = Field(default_factory=list)
  behaviour_factors: list[ScoreFactor] = Field(default_factory=list)
  metadata: dict = Field(default_factory=dict)
  store_mode: Literal["upsert", "append"] = "append"

  @model_validator(mode="after")
  def validate_scores(self):
    composite = round(
      self.device_score * 0.35 + self.user_score * 0.35 + self.behaviour_score * 0.30,
      2,
    )

    if composite < 0 or composite > 100:
      raise ValueError("Composite trust score must be between 0 and 100")

    return self


class TrustScoreCalculateRequest(BaseModel):
  user_id: str
  device_id: Optional[str] = None
  persist: bool = True


class TrustScoreListResponse(BaseModel):
  success: bool = True
  message: str
  items: list[TrustScorePublic]
  pagination: PaginationMeta


class TrustScoreDetailResponse(BaseModel):
  success: bool = True
  message: str
  trust_score: TrustScorePublic


class TrustScoreStoreResponse(BaseModel):
  success: bool = True
  message: str
  trust_score: TrustScorePublic
  store_mode: Literal["upsert", "append"]


class TrustScoreHistoryResponse(BaseModel):
  success: bool = True
  message: str
  user_id: str
  device_id: Optional[str] = None
  items: list[TrustScorePublic]
  pagination: PaginationMeta


class TrustScoreCalculateResponse(BaseModel):
  success: bool = True
  message: str
  trust_score: TrustScorePublic
  breakdown: TrustScoreBreakdown


class BehaviourEventCreateRequest(BehaviourEventCreate):
  pass


class BehaviourEventCreateResponse(BaseModel):
  success: bool = True
  message: str
  event: BehaviourEventPublic


class BehaviourEventListResponse(BaseModel):
  success: bool = True
  message: str
  items: list[BehaviourEventPublic]
  pagination: PaginationMeta


class TrustScoreComponentSummary(BaseModel):
  average_score: float
  min_score: float
  max_score: float
  total_evaluated: int


class TrustScoreStatsResponse(BaseModel):
  success: bool = True
  message: str
  total_scores: int
  access_allowed_count: int
  access_denied_count: int
  zero_trust_enabled: bool
  min_required_score: float
  average_composite_score: float
  device_score_summary: TrustScoreComponentSummary
  user_score_summary: TrustScoreComponentSummary
  behaviour_score_summary: TrustScoreComponentSummary
  trust_level_distribution: dict[str, int]
  calculated_at: datetime
