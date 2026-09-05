import { describe, expect, it } from "vitest";
import { isValidOptionalIpAddress } from "@/utils/ipAddress";

describe("isValidOptionalIpAddress", () => {
  it("allows empty values because IP is optional", () => {
    expect(isValidOptionalIpAddress("")).toBe(true);
    expect(isValidOptionalIpAddress("   ")).toBe(true);
  });

  it("accepts valid IPv4 addresses", () => {
    expect(isValidOptionalIpAddress("192.168.1.101")).toBe(true);
    expect(isValidOptionalIpAddress("0.0.0.0")).toBe(true);
  });

  it("rejects invalid IPv4 addresses", () => {
    expect(isValidOptionalIpAddress("192.168.1")).toBe(false);
    expect(isValidOptionalIpAddress("192.168.1.256")).toBe(false);
    expect(isValidOptionalIpAddress("192.168.1.01")).toBe(false);
    expect(isValidOptionalIpAddress("not-an-ip")).toBe(false);
  });

  it("accepts valid IPv6 addresses", () => {
    expect(isValidOptionalIpAddress("::1")).toBe(true);
    expect(isValidOptionalIpAddress("2001:db8::1")).toBe(true);
  });
});
