import axios, { type AxiosRequestHeaders } from "axios";
import { API_BASE_URL } from "@/config/env";
import {
  clearAuthTokens,
  getAccessToken,
  getRefreshToken,
  setAccessToken,
  setRefreshToken,
} from "@/utils";

type RefreshCallback = (token: string | null) => void;

let isRefreshing = false;
let refreshQueue: RefreshCallback[] = [];

function processRefreshQueue(token: string | null) {
  refreshQueue.forEach((callback) => callback(token));
  refreshQueue = [];
}

export function getStoredAccessToken(): string | null {
  return getAccessToken();
}

export function attachAuthHeader(headers: AxiosRequestHeaders, skipAuth = false): AxiosRequestHeaders {
  if (skipAuth) {
    return headers;
  }

  const token = getAccessToken();

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  return headers;
}

export function shouldSkipTokenRefresh(url?: string): boolean {
  if (!url) {
    return false;
  }

  return url.includes("/auth/login") || url.includes("/auth/refresh") || url.includes("/auth/register");
}

export async function refreshAccessToken(): Promise<string> {
  const refreshToken = getRefreshToken();

  if (!refreshToken) {
    clearAuthTokens();
    throw new Error("Session expired");
  }

  const response = await axios.post(
    `${API_BASE_URL}/auth/refresh`,
    { refresh_token: refreshToken },
    { headers: { "Content-Type": "application/json" } },
  );

  const { access_token: accessToken, refresh_token: newRefreshToken } = response.data;

  setAccessToken(accessToken);

  if (newRefreshToken) {
    setRefreshToken(newRefreshToken);
  }

  return accessToken;
}

export async function queueTokenRefresh(): Promise<string> {
  if (isRefreshing) {
    return new Promise((resolve, reject) => {
      refreshQueue.push((token) => {
        if (!token) {
          reject(new Error("Session expired"));
          return;
        }

        resolve(token);
      });
    });
  }

  isRefreshing = true;

  try {
    const accessToken = await refreshAccessToken();
    processRefreshQueue(accessToken);
    return accessToken;
  } catch (error) {
    clearAuthTokens();
    processRefreshQueue(null);
    throw error;
  } finally {
    isRefreshing = false;
  }
}

export function handleSessionExpired() {
  clearAuthTokens();

  if (window.location.pathname !== "/login") {
    window.location.assign("/login");
  }
}
