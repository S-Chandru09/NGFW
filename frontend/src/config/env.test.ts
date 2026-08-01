import { afterEach, describe, expect, it, vi } from "vitest";
import { buildWebSocketUrl } from "@/config/env";

describe("buildWebSocketUrl", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("builds an absolute websocket url with token query param", () => {
    vi.stubEnv("VITE_WS_BASE_URL", "ws://localhost:8000/ws");

    const url = buildWebSocketUrl("test-token");
    expect(url).toBe("ws://localhost:8000/ws?token=test-token");
  });

  it("builds a relative websocket url from the current host", () => {
    vi.stubEnv("VITE_WS_BASE_URL", "/ws");
    vi.stubGlobal("window", {
      location: {
        protocol: "https:",
        host: "dashboard.example.com",
      },
    });

    const url = buildWebSocketUrl("secure-token");
    expect(url).toBe("wss://dashboard.example.com/ws?token=secure-token");
  });
});
