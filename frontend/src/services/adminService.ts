import { apiService } from "@/services/api";
import type {
  AuditLog,
  FirewallRule,
  IOCListParams,
  LogListParams,
  PaginatedListResponse,
  RuleListParams,
  ThreatIOC,
  UserListItem,
  UserListParams,
} from "@/types/admin";

export async function fetchUsers(params: UserListParams = {}) {
  return apiService.get<PaginatedListResponse<UserListItem>>("/users", {
    params: {
      page: params.page,
      page_size: params.page_size,
      search: params.search,
      role: params.role,
      is_active: params.is_active,
    },
  });
}

export async function fetchFirewallRules(params: RuleListParams = {}) {
  return apiService.get<PaginatedListResponse<FirewallRule>>("/firewall-rules", {
    params: {
      page: params.page,
      page_size: params.page_size,
      action: params.action,
      is_enabled: params.is_enabled,
    },
  });
}

export async function fetchAuditLogs(params: LogListParams = {}) {
  return apiService.get<PaginatedListResponse<AuditLog>>("/logs", {
    params: {
      page: params.page,
      page_size: params.page_size,
      severity: params.severity,
      event_type: params.event_type,
      username: params.search,
    },
  });
}

export async function searchAuditLogs(params: LogListParams & { q?: string } = {}) {
  return apiService.get<PaginatedListResponse<AuditLog>>("/logs/search", {
    params: {
      page: params.page,
      page_size: params.page_size,
      q: params.q || params.search,
      severity: params.severity,
      event_type: params.event_type,
    },
  });
}

export async function fetchThreatIOCs(params: IOCListParams = {}) {
  return apiService.get<PaginatedListResponse<ThreatIOC>>("/threat-intelligence/iocs", {
    params: {
      page: params.page,
      page_size: params.page_size,
      ioc_type: params.ioc_type,
      threat_level: params.threat_level,
      is_malicious: params.is_malicious,
    },
  });
}

export async function searchThreatIOCs(params: IOCListParams & { q: string }) {
  return apiService.get<PaginatedListResponse<ThreatIOC>>("/threat-intelligence/iocs/search", {
    params: {
      page: params.page,
      page_size: params.page_size,
      q: params.q,
      ioc_type: params.ioc_type,
      threat_level: params.threat_level,
      is_malicious: params.is_malicious,
    },
  });
}

export async function deleteFirewallRule(ruleId: string) {
  return apiService.delete(`/firewall-rules/${ruleId}`);
}

export async function deleteAuditLog(logId: string) {
  return apiService.delete(`/logs/${logId}`);
}

export async function deleteThreatIOC(iocId: string) {
  return apiService.delete(`/threat-intelligence/iocs/${iocId}`);
}

export async function toggleFirewallRule(ruleId: string, isEnabled: boolean) {
  return apiService.patch(`/firewall-rules/${ruleId}`, {
    is_enabled: isEnabled,
  });
}
