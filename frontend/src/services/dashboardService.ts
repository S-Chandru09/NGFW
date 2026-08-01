import { apiService } from "@/services/api";
import type { DashboardStatisticsResponse, TrafficSummary } from "@/types/dashboard";

export async function fetchDashboardStatistics(
  periodHours = 24,
  topLimit = 10,
): Promise<DashboardStatisticsResponse> {
  return apiService.get<DashboardStatisticsResponse>("/dashboard/statistics", {
    params: {
      period_hours: periodHours,
      top_limit: topLimit,
    },
  });
}

export async function fetchTrafficSummary(periodHours = 24): Promise<TrafficSummary> {
  return apiService.get<TrafficSummary>("/dashboard/traffic-summary", {
    params: { period_hours: periodHours },
  });
}
