import type { PaginationMeta } from "@/types/admin";

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
  source_country?: string | null;
  destination_country?: string | null;
  is_automatic?: boolean;
  trigger_source?: string | null;
  created_by?: string | null;
  created_at: string;
  updated_at: string;
}

export interface FirewallRuleFormData {
  name: string;
  description: string;
  action: FirewallRuleAction;
  source_ip: string;
  destination_ip: string;
  source_port: string;
  destination_port: string;
  protocol: FirewallProtocol;
  priority: number;
  is_enabled: boolean;
  expires_at: string;
  source_country: string;
  destination_country: string;
}

export interface FirewallRuleListResponse {
  success: boolean;
  message: string;
  items: FirewallRule[];
  pagination: PaginationMeta;
}

export interface FirewallRuleDetailResponse {
  success: boolean;
  message: string;
  rule: FirewallRule;
}

export interface FirewallRuleActionSummary {
  action: FirewallRuleAction;
  total: number;
  enabled: number;
  disabled: number;
  expired: number;
}

export interface FirewallRuleStatsResponse {
  success: boolean;
  message: string;
  total_rules: number;
  enabled_rules: number;
  disabled_rules: number;
  expired_rules: number;
  action_summary: FirewallRuleActionSummary[];
}

export interface FirewallRuleListParams {
  page?: number;
  page_size?: number;
  action?: FirewallRuleAction;
  is_enabled?: boolean;
  is_expired?: boolean;
}

export const EMPTY_FIREWALL_RULE_FORM: FirewallRuleFormData = {
  name: "",
  description: "",
  action: "block",
  source_ip: "",
  destination_ip: "",
  source_port: "",
  destination_port: "",
  protocol: "any",
  priority: 100,
  is_enabled: true,
  expires_at: "",
  source_country: "",
  destination_country: "",
};
