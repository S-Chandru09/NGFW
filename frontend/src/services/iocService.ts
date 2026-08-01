import { apiService } from "@/services/api";
import type {
  IOCDetailResponse,
  IOCFormData,
  IOCListResponse,
  IOCStatsResponse,
  IOCType,
} from "@/types/ioc";

export async function fetchIOCStats() {
  return apiService.get<IOCStatsResponse>("/ioc-database/stats");
}

export async function fetchIOCIndicators(
  type: IOCType,
  params: { page?: number; page_size?: number; search?: string } = {},
) {
  if (params.search?.trim()) {
    return apiService.get<IOCListResponse>("/ioc-database/search", {
      params: {
        q: params.search,
        ioc_type: type,
        page: params.page,
        page_size: params.page_size,
      },
    });
  }

  return apiService.get<IOCListResponse>(`/ioc-database/${type}`, {
    params: {
      page: params.page,
      page_size: params.page_size,
    },
  });
}

export async function createIPIndicator(form: IOCFormData) {
  return apiService.post<IOCDetailResponse>("/ioc-database/ip", {
    ip_address: form.value.trim(),
    reputation_score: form.reputation_score,
    is_malicious: form.is_malicious,
    source: form.source,
    description: form.description || undefined,
    country: form.country || undefined,
    tags: form.tags ? form.tags.split(",").map((tag) => tag.trim()).filter(Boolean) : [],
    is_active: form.is_active,
  });
}

export async function createDomainIndicator(form: IOCFormData) {
  return apiService.post<IOCDetailResponse>("/ioc-database/domain", {
    domain: form.value.trim().toLowerCase(),
    reputation_score: form.reputation_score,
    is_malicious: form.is_malicious,
    source: form.source,
    description: form.description || undefined,
    tags: form.tags ? form.tags.split(",").map((tag) => tag.trim()).filter(Boolean) : [],
    is_active: form.is_active,
  });
}

export async function createHashIndicator(form: IOCFormData) {
  return apiService.post<IOCDetailResponse>("/ioc-database/hash", {
    hash_value: form.value.trim().toLowerCase(),
    reputation_score: form.reputation_score,
    is_malicious: form.is_malicious,
    source: form.source,
    description: form.description || undefined,
    tags: form.tags ? form.tags.split(",").map((tag) => tag.trim()).filter(Boolean) : [],
    is_active: form.is_active,
  });
}

export async function updateIOCIndicator(
  iocId: string,
  updates: Partial<{
    reputation_score: number;
    is_malicious: boolean;
    is_active: boolean;
    description: string;
    source: string;
    country: string;
    tags: string[];
  }>,
) {
  return apiService.patch<IOCDetailResponse>(`/ioc-database/${iocId}`, updates);
}

export async function deleteIOCIndicator(iocId: string) {
  return apiService.delete(`/ioc-database/${iocId}`);
}

export async function checkIOCIndicator(type: IOCType, value: string) {
  return apiService.get(`/ioc-database/${type}/check/${encodeURIComponent(value)}`);
}
