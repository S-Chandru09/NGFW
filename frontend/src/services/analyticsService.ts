import { apiService } from "@/services/api";
import type { AnalyticsOverview } from "@/types/analytics";

export async function fetchAnalyticsOverview(params: {
  days?: number;
  months?: number;
  period_hours?: number;
}) {
  return apiService.get<AnalyticsOverview>("/analytics/overview", { params });
}

export async function fetchDailyAnalytics(days: number) {
  return apiService.get<AnalyticsOverview["daily"]>("/analytics/daily", {
    params: { days },
  });
}

export async function fetchMonthlyAnalytics(months: number) {
  return apiService.get<AnalyticsOverview["monthly"]>("/analytics/monthly", {
    params: { months },
  });
}

export async function fetchProtocolAnalytics(periodHours: number) {
  return apiService.get<AnalyticsOverview["protocols"]>("/analytics/protocols", {
    params: { period_hours: periodHours },
  });
}

export async function fetchCountryAnalytics(periodHours: number, limit = 20) {
  return apiService.get<AnalyticsOverview["countries"]>("/analytics/countries", {
    params: { period_hours: periodHours, limit },
  });
}
