import { useCallback, useEffect, useState } from "react";
import { getApiErrorMessage } from "@/services/apiClient";
import { fetchDashboardStatistics } from "@/services/dashboardService";
import type { DashboardStatisticsResponse } from "@/types/dashboard";

interface UseThreatAnalyticsOptions {
  periodHours?: number;
  topLimit?: number;
  refreshIntervalMs?: number;
  enabled?: boolean;
}

export function useThreatAnalytics({
  periodHours = 24,
  topLimit = 10,
  refreshIntervalMs = 60000,
  enabled = true,
}: UseThreatAnalyticsOptions = {}) {
  const [data, setData] = useState<DashboardStatisticsResponse | null>(null);
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
      const response = await fetchDashboardStatistics(periodHours, topLimit);
      setData(response);
      setError(null);
      setLastUpdated(new Date());
    } catch (refreshError) {
      setError(getApiErrorMessage(refreshError, "Failed to load threat analytics"));
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, [enabled, periodHours, topLimit]);

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
