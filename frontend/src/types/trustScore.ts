import type { PaginationMeta } from "@/types/admin";

export type TrustLevel = "critical" | "low" | "medium" | "high" | "verified";

export interface ScoreFactor {
  factor: string;
  impact: number;
  description: string;
}

export interface TrustScoreBreakdown {
  device_score: number;
  user_score: number;
  behaviour_score: number;
  composite_score: number;
  trust_level: TrustLevel;
  is_access_allowed: boolean;
  min_required_score: number;
  device_factors: ScoreFactor[];
  user_factors: ScoreFactor[];
  behaviour_factors: ScoreFactor[];
}

export interface TrustScore {
  id: string;
  score_id: string;
  user_id: string;
  device_id?: string | null;
  username?: string | null;
  device_name?: string | null;
  device_score: number;
  user_score: number;
  behaviour_score: number;
  composite_score: number;
  trust_level: TrustLevel;
  is_access_allowed: boolean;
  breakdown: TrustScoreBreakdown;
  metadata?: Record<string, unknown>;
  calculated_at: string;
  created_at: string;
  updated_at: string;
}

export interface TrustScoreListResponse {
  success: boolean;
  message: string;
  items: TrustScore[];
  pagination: PaginationMeta;
}

export interface TrustScoreDetailResponse {
  success: boolean;
  message: string;
  trust_score: TrustScore;
}

export interface TrustScoreComponentSummary {
  average_score: number;
  min_score: number;
  max_score: number;
  total_evaluated: number;
}

export interface TrustScoreStatsResponse {
  success: boolean;
  message: string;
  total_scores: number;
  access_allowed_count: number;
  access_denied_count: number;
  zero_trust_enabled: boolean;
  min_required_score: number;
  average_composite_score: number;
  device_score_summary: TrustScoreComponentSummary;
  user_score_summary: TrustScoreComponentSummary;
  behaviour_score_summary: TrustScoreComponentSummary;
  trust_level_distribution: Record<string, number>;
  calculated_at: string;
}

export interface ZeroTrustDashboardData {
  stats: TrustScoreStatsResponse;
  recentScores: TrustScore[];
  currentUserScore: TrustScore | null;
}
