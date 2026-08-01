export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface ApiValidationErrorItem {
  field: string;
  message: string;
}

export interface ApiErrorPayload {
  detail?: string | ApiValidationErrorItem[];
  message?: string;
  success?: boolean;
}

export interface ApiRequestConfig {
  params?: Record<string, unknown>;
  headers?: Record<string, string>;
  skipAuth?: boolean;
  timeout?: number;
}
