import { useCallback, useEffect, useState } from "react";
import { getApiErrorMessage } from "@/services/apiClient";
import {
  fetchTrustScoreStats,
  fetchTrustScores,
  fetchUserTrustScore,
} from "@/services/trustScoreService";
import type { ZeroTrustDashboardData } from "@/types/trustScore";

interface UseZeroTrustDashboardOptions {
  userId?: string;
  refreshIntervalMs?: number;
  enabled?: boolean;
}

export function useZeroTrustDashboard({
  userId,
  refreshIntervalMs = 60000,
  enabled = true,
}: UseZeroTrustDashboardOptions = {}) {
  const [data, setData] = useState<ZeroTrustDashboardData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const refresh = useCallback(async (showRefreshing = false) => {
    if (!enabled) {
      return;
    }

    if (showRefreshing) {
      setIsRefreshing(true);
    }

    try {
      const [stats, recentScoresResponse, currentUserScoreResponse] = await Promise.all([
        fetchTrustScoreStats(),
        fetchTrustScores({ page: 1, page_size: 12 }),
        userId
          ? fetchUserTrustScore(userId).catch(() => null)
          : Promise.resolve(null),
      ]);

      setData({
        stats,
        recentScores: recentScoresResponse.items,
        currentUserScore: currentUserScoreResponse?.trust_score ?? null,
      });
      setError(null);
      setLastUpdated(new Date());
    } catch (refreshError) {
      setError(getApiErrorMessage(refreshError, "Failed to load Zero Trust dashboard"));
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, [enabled, userId]);

  useEffect(() => {
    setIsLoading(true);
    refresh(false);
  }, [refresh]);

  useEffect(() => {
    if (!enabled || refreshIntervalMs <= 0) {
      return;
    }

    const intervalId = window.setInterval(() => refresh(true), refreshIntervalMs);
    return () => window.clearInterval(intervalId);
  }, [enabled, refresh, refreshIntervalMs]);

  return {
    data,
    isLoading,
    isRefreshing,
    error,
    lastUpdated,
    refresh: () => refresh(true),
  };
}
