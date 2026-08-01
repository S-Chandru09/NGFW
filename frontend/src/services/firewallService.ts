import { apiService } from "@/services/api";
import type {
  FirewallRule,
  FirewallRuleDetailResponse,
  FirewallRuleFormData,
  FirewallRuleListParams,
  FirewallRuleListResponse,
  FirewallRuleStatsResponse,
} from "@/types/firewall";

function toPayload(form: FirewallRuleFormData) {
  const payload: Record<string, unknown> = {
    name: form.name.trim(),
    description: form.description.trim() || undefined,
    action: form.action,
    source_ip: form.source_ip.trim() || undefined,
    destination_ip: form.destination_ip.trim() || undefined,
    source_port: form.source_port ? Number(form.source_port) : undefined,
    destination_port: form.destination_port ? Number(form.destination_port) : undefined,
    protocol: form.protocol,
    priority: form.priority,
    is_enabled: form.is_enabled,
    source_country: form.source_country.trim().toUpperCase() || undefined,
    destination_country: form.destination_country.trim().toUpperCase() || undefined,
  };

  if (form.action === "temporary_block" && form.expires_at) {
    payload.expires_at = new Date(form.expires_at).toISOString();
  }

  return payload;
}

export async function fetchFirewallRules(params: FirewallRuleListParams = {}) {
  return apiService.get<FirewallRuleListResponse>("/firewall-rules", {
    params: {
      page: params.page,
      page_size: params.page_size,
      action: params.action,
      is_enabled: params.is_enabled,
      is_expired: params.is_expired,
    },
  });
}

export async function fetchFirewallRuleStats() {
  return apiService.get<FirewallRuleStatsResponse>("/firewall-rules/stats");
}

export async function fetchFirewallRule(ruleId: string) {
  return apiService.get<FirewallRuleDetailResponse>(`/firewall-rules/${ruleId}`);
}

export async function createFirewallRule(form: FirewallRuleFormData) {
  return apiService.post<FirewallRuleDetailResponse>("/firewall-rules", toPayload(form));
}

export async function updateFirewallRule(ruleId: string, form: FirewallRuleFormData) {
  return apiService.patch<FirewallRuleDetailResponse>(`/firewall-rules/${ruleId}`, toPayload(form));
}

export async function deleteFirewallRule(ruleId: string) {
  return apiService.delete(`/firewall-rules/${ruleId}`);
}

export async function toggleFirewallRule(ruleId: string, isEnabled: boolean) {
  return apiService.patch<FirewallRuleDetailResponse>(`/firewall-rules/${ruleId}`, {
    is_enabled: isEnabled,
  });
}

export function ruleToFormData(rule: FirewallRule): FirewallRuleFormData {
  return {
    name: rule.name,
    description: rule.description ?? "",
    action: rule.action,
    source_ip: rule.source_ip ?? "",
    destination_ip: rule.destination_ip ?? "",
    source_port: rule.source_port?.toString() ?? "",
    destination_port: rule.destination_port?.toString() ?? "",
    protocol: rule.protocol,
    priority: rule.priority,
    is_enabled: rule.is_enabled,
    expires_at: rule.expires_at ? rule.expires_at.slice(0, 16) : "",
    source_country: rule.source_country ?? "",
    destination_country: rule.destination_country ?? "",
  };
}
