import type { UserProfile } from "@/types";

export interface PaginationMeta {
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
  has_next: boolean;
  has_previous: boolean;
}

export interface PaginatedListResponse<T> {
  success: boolean;
  message: string;
  items: T[];
  pagination: PaginationMeta;
}

export type AdminTab = "users" | "rules" | "logs" | "threat-intelligence";

export type LogSeverity = "info" | "warning" | "error" | "critical";

export type LogEventType =
  | "auth"
  | "firewall"
  | "threat"
  | "policy"
  | "network"
  | "system"
  | "ml"
  | "device"
  | "access";

export interface AuditLog {
  id: string;
  log_id: string;
  event_type: LogEventType;
  severity: LogSeverity;
  message: string;
  description?: string | null;
  user_id?: string | null;
  username?: string | null;
  ip_address?: string | null;
  source: string;
  resource_type?: string | null;
  resource_id?: string | null;
  created_at: string;
}

export type FirewallRuleAction =
  | "allow"
  | "block"
  | "whitelist"
  | "blacklist"
  | "temporary_block";

export type FirewallProtocol = "tcp" | "udp" | "icmp" | "any";

export interface FirewallRule {
  id: string;
  rule_id: string;
  name: string;
  description?: string | null;
  action: FirewallRuleAction;
  source_ip?: string | null;
  destination_ip?: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  protocol: FirewallProtocol;
  priority: number;
  is_enabled: boolean;
  expires_at?: string | null;
  is_expired: boolean;
  created_by?: string | null;
  created_at: string;
  updated_at: string;
}

export type IOCType = "ip" | "hash" | "domain" | "url" | "email";

export type ThreatIntelLevel = "safe" | "low" | "medium" | "high" | "critical";

export interface ThreatIOC {
  id: string;
  ioc_id: string;
  ioc_type: IOCType;
  value: string;
  reputation_score: number;
  threat_level: ThreatIntelLevel;
  is_malicious: boolean;
  threat_categories: string[];
  source: string;
  description?: string | null;
  tags: string[];
  is_active: boolean;
  hit_count: number;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
}

export type UserListItem = UserProfile;

export interface ListParams {
  page?: number;
  page_size?: number;
  search?: string;
}

export interface UserListParams extends ListParams {
  role?: string;
  is_active?: boolean;
}

export interface LogListParams extends ListParams {
  severity?: LogSeverity;
  event_type?: LogEventType;
}

export interface RuleListParams extends ListParams {
  action?: FirewallRuleAction;
  is_enabled?: boolean;
}

export interface IOCListParams extends ListParams {
  ioc_type?: IOCType;
  threat_level?: ThreatIntelLevel;
  is_malicious?: boolean;
}
