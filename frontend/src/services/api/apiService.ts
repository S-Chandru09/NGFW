import type { AxiosRequestConfig } from "axios";
import { apiClient } from "@/services/api/apiClient";
import { normalizeApiError } from "@/services/api/errors";
import type { ApiRequestConfig } from "@/types/api";

type ServiceRequestConfig = ApiRequestConfig & Partial<Pick<AxiosRequestConfig, "responseType">>;

function toAxiosConfig(config: ServiceRequestConfig = {}): AxiosRequestConfig & { skipAuth?: boolean } {
  return {
    params: config.params,
    headers: config.headers,
    timeout: config.timeout,
    responseType: config.responseType,
    skipAuth: config.skipAuth,
  };
}

async function request<T>(method: string, url: string, data?: unknown, config: ServiceRequestConfig = {}) {
  try {
    const response = await apiClient.request<T>({
      method,
      url,
      data,
      ...toAxiosConfig(config),
    });

    return response.data;
  } catch (error) {
    throw normalizeApiError(error);
  }
}

export const apiService = {
  get<T>(url: string, config?: ServiceRequestConfig) {
    return request<T>("GET", url, undefined, config);
  },

  post<T>(url: string, data?: unknown, config?: ServiceRequestConfig) {
    return request<T>("POST", url, data, config);
  },

  put<T>(url: string, data?: unknown, config?: ServiceRequestConfig) {
    return request<T>("PUT", url, data, config);
  },

  patch<T>(url: string, data?: unknown, config?: ServiceRequestConfig) {
    return request<T>("PATCH", url, data, config);
  },

  delete<T>(url: string, config?: ServiceRequestConfig) {
    return request<T>("DELETE", url, undefined, config);
  },
};
