export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

export const WS_BASE_URL =
  import.meta.env.VITE_WS_BASE_URL || "ws://localhost:8000/ws";

export const APP_NAME =
  import.meta.env.VITE_APP_NAME || "AI-NGFW Dashboard";

export const APP_VERSION =
  import.meta.env.VITE_APP_VERSION || "1.0.0";

export const REQUEST_TIMEOUT_MS = 30000;

export function buildWebSocketUrl(token: string): string {
  const configuredUrl = import.meta.env.VITE_WS_BASE_URL || "/ws";

  if (configuredUrl.startsWith("ws://") || configuredUrl.startsWith("wss://")) {
    const url = new URL(configuredUrl);
    url.searchParams.set("token", token);
    return url.toString();
  }

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const normalizedPath = configuredUrl.startsWith("/") ? configuredUrl : `/${configuredUrl}`;
  return `${protocol}//${window.location.host}${normalizedPath}?token=${encodeURIComponent(token)}`;
}
