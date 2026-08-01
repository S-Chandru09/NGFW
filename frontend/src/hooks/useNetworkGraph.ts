import { useCallback, useEffect, useState } from "react";
import { getApiErrorMessage } from "@/services/apiClient";
import { fetchNetworkGraph } from "@/services/networkGraphService";
import type { NetworkGraphResponse } from "@/types/networkGraph";

interface UseNetworkGraphOptions {
  periodHours?: number;
  maxNodes?: number;
  refreshIntervalMs?: number;
}

export function useNetworkGraph({
  periodHours = 24,
  maxNodes = 40,
  refreshIntervalMs = 60000,
}: UseNetworkGraphOptions = {}) {
  const [data, setData] = useState<NetworkGraphResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async (showRefreshing = false) => {
    if (showRefreshing) {
      setIsRefreshing(true);
    }

    try {
      const response = await fetchNetworkGraph(periodHours, maxNodes);
      setData(response);
      setError(null);
    } catch (refreshError) {
      setError(getApiErrorMessage(refreshError, "Failed to load network graph"));
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, [maxNodes, periodHours]);

  useEffect(() => {
    setIsLoading(true);
    refresh(false);
  }, [refresh]);

  useEffect(() => {
    if (refreshIntervalMs <= 0) {
      return;
    }

    const intervalId = window.setInterval(() => refresh(true), refreshIntervalMs);
    return () => window.clearInterval(intervalId);
  }, [refresh, refreshIntervalMs]);

  return {
    data,
    isLoading,
    isRefreshing,
    error,
    refresh: () => refresh(true),
  };
}
