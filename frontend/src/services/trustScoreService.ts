import { apiService } from "@/services/api";
import type {
  TrustScoreDetailResponse,
  TrustScoreListResponse,
  TrustScoreStatsResponse,
} from "@/types/trustScore";

export async function fetchTrustScoreStats() {
  return apiService.get<TrustScoreStatsResponse>("/trust-scores/stats");
}

export async function fetchTrustScores(params: {
  page?: number;
  page_size?: number;
  sort_by?: string;
  sort_order?: string;
} = {}) {
  return apiService.get<TrustScoreListResponse>("/trust-scores", {
    params: {
      page: params.page,
      page_size: params.page_size,
      sort_by: params.sort_by ?? "calculated_at",
      sort_order: params.sort_order ?? "desc",
    },
  });
}

export async function fetchUserTrustScore(userId: string, deviceId?: string) {
  return apiService.get<TrustScoreDetailResponse>(`/trust-scores/user/${userId}`, {
    params: deviceId ? { device_id: deviceId } : undefined,
  });
}

export async function calculateTrustScore(userId: string, deviceId?: string) {
  return apiService.post<TrustScoreDetailResponse & { breakdown: unknown }>(
    "/trust-scores/calculate",
    {
      user_id: userId,
      device_id: deviceId,
      persist: true,
    },
  );
}
