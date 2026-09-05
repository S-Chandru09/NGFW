from typing import Any, Optional

WILDCARD_TOKENS = {"any", "*"}
UNRESTRICTED_PROTOCOL = "any"


def is_unrestricted_value(value: Any) -> bool:
  if value is None:
    return True

  if isinstance(value, str):
    normalized = value.strip().lower()
    return normalized == "" or normalized in WILDCARD_TOKENS

  return False


def normalize_ip_constraint(value: Any) -> Optional[str]:
  if is_unrestricted_value(value):
    return None

  if isinstance(value, str):
    return value.strip()

  return value


def normalize_port_constraint(value: Any) -> Optional[int]:
  if is_unrestricted_value(value):
    return None

  if isinstance(value, str) and value.strip().isdigit():
    return int(value.strip())

  return value


def normalize_protocol_constraint(value: Any) -> Any:
  if is_unrestricted_value(value):
    return UNRESTRICTED_PROTOCOL

  if isinstance(value, str):
    return value.strip().lower()

  return value
