export interface ProtocolTraffic {
  protocol: string;
  flow_count: number;
  total_bytes: number;
  percentage: number;
}

export interface HourlyTrafficPoint {
  hour: string;
  flow_count: number;
  total_bytes: number;
  threat_count: number;
}

export interface TrafficSummary {
  success: boolean;
  message: string;
  total_flows: number;
  total_bytes: number;
  total_packets: number;
  inbound_bytes: number;
  outbound_bytes: number;
  allowed_flows: number;
  blocked_flows: number;
  threat_flows: number;
  unique_source_ips: number;
  unique_destination_ips: number;
  protocols: ProtocolTraffic[];
  hourly_trend: HourlyTrafficPoint[];
  period_hours: number;
  generated_at: string;
}

export interface AttackCountBreakdown {
  total_attacks: number;
  attacks_today: number;
  attacks_this_week: number;
  attacks_this_month: number;
  blocked_attacks: number;
  active_alerts: number;
  resolved_alerts: number;
  critical_attacks: number;
  high_attacks: number;
  medium_attacks: number;
  low_attacks: number;
}

export interface ThreatLevelBreakdown {
  overall_score: number;
  overall_level: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  risk_trend: string;
  last_incident_at: string | null;
}

export interface AttackTypeItem {
  threat_type: string;
  count: number;
  percentage: number;
  severity: string;
  last_detected_at: string | null;
}

export interface ThreatAlertItem {
  alert_id: string;
  threat_type: string;
  severity: string;
  status: string;
  source_ip?: string | null;
  destination_ip?: string | null;
  flow_id?: string | null;
  confidence?: number | null;
  detected_at: string;
  upload_id?: string | null;
  original_filename?: string | null;
  analysis_source?: string | null;
}

export interface DashboardKPI {
  label: string;
  value: number | string;
  unit?: string | null;
  change_percentage?: number | null;
  trend?: string | null;
}

export interface DashboardStatisticsData {
  traffic_summary: TrafficSummary;
  attack_count: AttackCountBreakdown;
  threat_level: ThreatLevelBreakdown;
  top_attack_types: AttackTypeItem[];
  recent_threat_alerts: ThreatAlertItem[];
  kpis: DashboardKPI[];
  firewall_rules_active: number;
  firewall_rules_total: number;
  trusted_devices: number;
  total_devices: number;
  zero_trust_enabled: boolean;
}

export interface DashboardStatisticsResponse {
  success: boolean;
  message: string;
  data: DashboardStatisticsData;
  generated_at: string;
}
