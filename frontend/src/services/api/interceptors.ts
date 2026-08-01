import type { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from "axios";
import {
  attachAuthHeader,
  handleSessionExpired,
  queueTokenRefresh,
  shouldSkipTokenRefresh,
} from "@/services/api/auth";
import { normalizeApiError } from "@/services/api/errors";

type RetryableRequestConfig = InternalAxiosRequestConfig & {
  _retry?: boolean;
  skipAuth?: boolean;
};

export function setupRequestInterceptor(client: AxiosInstance) {
  client.interceptors.request.use((config: RetryableRequestConfig) => {
    config.headers = attachAuthHeader(config.headers, config.skipAuth);
    return config;
  });
}

export function setupResponseInterceptor(client: AxiosInstance) {
  client.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
      const originalRequest = error.config as RetryableRequestConfig | undefined;

      if (
        error.response?.status !== 401 ||
        !originalRequest ||
        originalRequest._retry ||
        originalRequest.skipAuth ||
        shouldSkipTokenRefresh(originalRequest.url)
      ) {
        return Promise.reject(normalizeApiError(error));
      }

      originalRequest._retry = true;

      try {
        const accessToken = await queueTokenRefresh();
        originalRequest.headers.Authorization = `Bearer ${accessToken}`;
        return client(originalRequest);
      } catch (refreshError) {
        handleSessionExpired();
        return Promise.reject(normalizeApiError(refreshError));
      }
    },
  );
}
