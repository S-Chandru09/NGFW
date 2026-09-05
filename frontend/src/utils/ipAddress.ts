const IPV4_OCTET = /^(?:0|[1-9]\d{0,2})$/;

export function isValidIPv4(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    if (!IPV4_OCTET.test(part)) {
      return false;
    }

    const octet = Number(part);
    return octet >= 0 && octet <= 255;
  });
}

export function isValidIPv6(value: string): boolean {
  try {
    const parsed = new URL(`http://[${value}]`);
    return Boolean(parsed.hostname);
  } catch {
    return false;
  }
}

export function isValidOptionalIpAddress(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) {
    return true;
  }

  return trimmed.includes(":") ? isValidIPv6(trimmed) : isValidIPv4(trimmed);
}
