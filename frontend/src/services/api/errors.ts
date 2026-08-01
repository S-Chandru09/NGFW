import axios, { AxiosError } from "axios";
import type { ApiErrorPayload, ApiValidationErrorItem } from "@/types/api";

export type ApiErrorCode =
  | "NETWORK_ERROR"
  | "TIMEOUT"
  | "UNAUTHORIZED"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "VALIDATION_ERROR"
  | "SERVER_ERROR"
  | "UNKNOWN";

export class ApiError extends Error {
  readonly status: number;
  readonly code: ApiErrorCode;
  readonly payload: unknown;
  readonly validationErrors: ApiValidationErrorItem[];

  constructor(
    message: string,
    status = 0,
    code: ApiErrorCode = "UNKNOWN",
    payload: unknown = null,
    validationErrors: ApiValidationErrorItem[] = [],
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.payload = payload;
    this.validationErrors = validationErrors;
  }
}

function parseValidationErrors(detail: unknown): ApiValidationErrorItem[] {
  if (!Array.isArray(detail)) {
    return [];
  }

  return detail.map((item) => ({
    field: Array.isArray(item?.loc) ? item.loc.join(".") : "request",
    message: typeof item?.msg === "string" ? item.msg : "Validation failed",
  }));
}

function extractErrorMessage(payload: unknown, fallback: string): string {
  if (typeof payload === "string" && payload.trim()) {
    return payload;
  }

  if (payload && typeof payload === "object") {
    const data = payload as ApiErrorPayload;

    if (typeof data.message === "string" && data.message.trim()) {
      return data.message;
    }

    if (typeof data.detail === "string" && data.detail.trim()) {
      return data.detail;
    }

    if (Array.isArray(data.detail) && data.detail.length > 0) {
      const first = data.detail[0];

      if (typeof first === "string") {
        return first;
      }

      if (first && typeof first === "object" && "msg" in first) {
        return String((first as { msg: unknown }).msg);
      }
    }
  }

  return fallback;
}

function resolveErrorCode(status: number, validationErrors: ApiValidationErrorItem[]): ApiErrorCode {
  if (validationErrors.length > 0) {
    return "VALIDATION_ERROR";
  }

  if (status === 401) {
    return "UNAUTHORIZED";
  }

  if (status === 403) {
    return "FORBIDDEN";
  }

  if (status === 404) {
    return "NOT_FOUND";
  }

  if (status >= 500) {
    return "SERVER_ERROR";
  }

  return "UNKNOWN";
}

export function normalizeApiError(error: unknown, fallback = "Request failed"): ApiError {
  if (error instanceof ApiError) {
    return error;
  }

  if (axios.isAxiosError(error)) {
    const axiosError = error as AxiosError<ApiErrorPayload>;

    if (axiosError.code === "ECONNABORTED") {
      return new ApiError("Request timed out", 408, "TIMEOUT", axiosError.response?.data);
    }

    if (!axiosError.response) {
      return new ApiError(
        axiosError.message || "Network request failed",
        0,
        "NETWORK_ERROR",
        null,
      );
    }

    const { status, data } = axiosError.response;
    const validationErrors = parseValidationErrors(data?.detail);
    const message = extractErrorMessage(data, fallback);
    const code = resolveErrorCode(status, validationErrors);

    return new ApiError(message, status, code, data, validationErrors);
  }

  if (error instanceof Error) {
    return new ApiError(error.message, 0, "UNKNOWN");
  }

  return new ApiError(fallback, 0, "UNKNOWN");
}

export function getApiErrorMessage(error: unknown, fallback = "Request failed"): string {
  return normalizeApiError(error, fallback).message;
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

export function isAuthError(error: unknown): boolean {
  return isApiError(error) && (error.code === "UNAUTHORIZED" || error.status === 401);
}

export function isValidationError(error: unknown): boolean {
  return isApiError(error) && error.code === "VALIDATION_ERROR";
}
