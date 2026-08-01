from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4

from jose import JWTError, jwt
from pydantic import BaseModel, Field

from config import settings


class TokenPayload(BaseModel):
  sub: str = Field(..., description="Subject - user ID")
  email: str
  username: str
  role: str
  token_type: str
  jti: str = Field(..., description="Unique token identifier")
  exp: int
  iat: int


def _utc_now() -> datetime:
  return datetime.now(timezone.utc)


def _to_timestamp(value: datetime) -> int:
  return int(value.timestamp())


def create_access_token(
  user_id: str,
  email: str,
  username: str,
  role: str,
  expires_delta: Optional[timedelta] = None,
) -> str:
  issued_at = _utc_now()
  expire_at = issued_at + (
    expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
  )

  payload = {
    "sub": user_id,
    "email": email,
    "username": username,
    "role": role,
    "token_type": "access",
    "jti": str(uuid4()),
    "iat": _to_timestamp(issued_at),
    "exp": _to_timestamp(expire_at),
  }

  return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def create_refresh_token(
  user_id: str,
  email: str,
  username: str,
  role: str,
  expires_delta: Optional[timedelta] = None,
) -> str:
  issued_at = _utc_now()
  expire_at = issued_at + (
    expires_delta or timedelta(days=settings.refresh_token_expire_days)
  )

  payload = {
    "sub": user_id,
    "email": email,
    "username": username,
    "role": role,
    "token_type": "refresh",
    "jti": str(uuid4()),
    "iat": _to_timestamp(issued_at),
    "exp": _to_timestamp(expire_at),
  }

  return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> dict[str, Any]:
  try:
    payload = jwt.decode(
      token,
      settings.secret_key,
      algorithms=[settings.algorithm],
    )
    return payload
  except JWTError as exc:
    raise ValueError(f"Invalid token: {exc}") from exc


def verify_access_token(token: str) -> TokenPayload:
  payload = decode_token(token)

  if payload.get("token_type") != "access":
    raise ValueError("Invalid access token type")

  return TokenPayload(**payload)


def verify_refresh_token(token: str) -> TokenPayload:
  payload = decode_token(token)

  if payload.get("token_type") != "refresh":
    raise ValueError("Invalid refresh token type")

  return TokenPayload(**payload)


def get_token_expiry_seconds(token_type: str = "access") -> int:
  if token_type == "refresh":
    return settings.refresh_token_expire_days * 24 * 60 * 60
  return settings.access_token_expire_minutes * 60
