export interface AnalyticsTotals {
  flow_count: number;
  total_bytes: number;
  total_packets: number;
  threat_count: number;
  blocked_count: number;
  allowed_count: number;
  unique_source_ips: number;
}

export interface AnalyticsTimePoint {
  period: string;
  flow_count: number;
  total_bytes: number;
  total_packets: number;
  threat_count: number;
  blocked_count: number;
  allowed_count: number;
  unique_source_ips: number;
}

export interface DailyAnalytics {
  success: boolean;
  message: string;
  days: number;
  start_date: string;
  end_date: string;
  data_points: AnalyticsTimePoint[];
  totals: AnalyticsTotals;
  generated_at: string;
}

export interface MonthlyAnalytics {
  success: boolean;
  message: string;
  months: number;
  start_period: string;
  end_period: string;
  data_points: AnalyticsTimePoint[];
  totals: AnalyticsTotals;
  generated_at: string;
}

export interface ProtocolAnalyticsItem {
  protocol: string;
  flow_count: number;
  total_bytes: number;
  total_packets: number;
  threat_count: number;
  blocked_count: number;
  percentage: number;
}

export interface ProtocolAnalytics {
  success: boolean;
  message: string;
  period_hours: number;
  total_flows: number;
  total_bytes: number;
  protocols: ProtocolAnalyticsItem[];
  generated_at: string;
}

export interface CountryAnalyticsItem {
  country_code: string;
  country_name: string;
  flow_count: number;
  total_bytes: number;
  threat_count: number;
  blocked_count: number;
  percentage: number;
  top_source_ips: string[];
}

export interface CountryAnalytics {
  success: boolean;
  message: string;
  period_hours: number;
  total_flows: number;
  total_bytes: number;
  countries: CountryAnalyticsItem[];
  unknown_flow_count: number;
  generated_at: string;
}

export interface AnalyticsOverview {
  success: boolean;
  message: string;
  daily: DailyAnalytics;
  monthly: MonthlyAnalytics;
  protocols: ProtocolAnalytics;
  countries: CountryAnalytics;
  generated_at: string;
}

export interface AnalyticsFiltersState {
  days: number;
  months: number;
  periodHours: number;
}

export const DEFAULT_ANALYTICS_FILTERS: AnalyticsFiltersState = {
  days: 30,
  months: 12,
  periodHours: 24,
};

export type AnalyticsDashboardTab = "charts" | "tables";
