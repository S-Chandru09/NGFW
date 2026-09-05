import { describe, expect, it } from "vitest";
import {
  EMPTY_DEVICE_FORM,
  buildDeviceCreatePayload,
  buildDeviceUpdatePayload,
} from "@/types/device";

describe("device payload builders", () => {
  it("omits trust_score and is_trusted from create payloads", () => {
    const payload = buildDeviceCreatePayload({
      ...EMPTY_DEVICE_FORM,
      device_name: "E2E Test Device",
      device_type: "desktop",
      os_type: "Windows",
      ip_address: "192.168.1.101",
      user_id: "6a9b0bffd1e8df398321245f",
    });

    expect(payload).toEqual({
      device_name: "E2E Test Device",
      device_type: "desktop",
      os_type: "Windows",
      ip_address: "192.168.1.101",
      user_id: "6a9b0bffd1e8df398321245f",
    });
    expect(payload).not.toHaveProperty("trust_score");
    expect(payload).not.toHaveProperty("is_trusted");
  });

  it("omits empty optional create fields and never sends trust outputs", () => {
    const payload = buildDeviceCreatePayload({
      ...EMPTY_DEVICE_FORM,
      device_name: "  Laptop  ",
    });

    expect(payload).toEqual({
      device_name: "Laptop",
      device_type: "unknown",
    });
    expect(payload).not.toHaveProperty("trust_score");
    expect(payload).not.toHaveProperty("is_trusted");
  });

  it("sends inventory fields on update without trust_score or is_trusted", () => {
    const payload = buildDeviceUpdatePayload({
      device_name: "E2E Test Device",
      device_type: "desktop",
      os_type: "Windows",
      ip_address: "192.168.1.101",
      user_id: "",
      is_compliant: true,
    });

    expect(payload).toEqual({
      device_name: "E2E Test Device",
      device_type: "desktop",
      os_type: "Windows",
      ip_address: "192.168.1.101",
      user_id: null,
      is_compliant: true,
    });
    expect(payload).not.toHaveProperty("trust_score");
    expect(payload).not.toHaveProperty("is_trusted");
  });
});
