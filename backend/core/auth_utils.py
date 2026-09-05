from datetime import datetime, timezone
from typing import Callable, Optional

from bson import ObjectId
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer

from config import settings
from core.jwt_handler import TokenPayload, create_access_token, create_refresh_token, verify_access_token
from core.password import verify_password
from database import get_users_collection
from models.user import UserInDB, UserPublic, UserRole, UserDocument

oauth2_scheme = OAuth2PasswordBearer(
  tokenUrl=f"{settings.api_v1_prefix}/auth/login/form",
  auto_error=False,
)


class AuthenticationError(Exception):
  def __init__(self, message: str = "Authentication failed") -> None:
    self.message = message
    super().__init__(self.message)


class TokenData:
  def __init__(self, payload: TokenPayload) -> None:
    self.user_id: str = payload.sub
    self.email: str = payload.email
    self.username: str = payload.username
    self.role: UserRole = UserRole(payload.role)
    self.token_type: str = payload.token_type
    self.jti: str = payload.jti


ROLE_PERMISSIONS: dict[UserRole, set[str]] = {
  UserRole.ADMIN: {
    "users:read",
    "users:write",
    "users:delete",
    "policies:read",
    "policies:write",
    "policies:delete",
    "firewall:read",
    "firewall:write",
    "firewall:delete",
    "threats:read",
    "threats:write",
    "alerts:read",
    "alerts:write",
    "incidents:read",
    "incidents:write",
    "incidents:respond",
    "network:read",
    "network:write",
    "devices:read",
    "devices:write",
    "trust:read",
    "trust:write",
    "audit:read",
    "dashboard:read",
    "capture:read",
    "capture:write",
    "ml:read",
    "ml:write",
  },
  UserRole.ANALYST: {
    "users:read",
    "policies:read",
    "firewall:read",
    "firewall:write",
    "threats:read",
    "threats:write",
    "alerts:read",
    "alerts:write",
    "incidents:read",
    "incidents:write",
    "incidents:respond",
    "network:read",
    "network:write",
    "devices:read",
    "trust:read",
    "trust:write",
    "audit:read",
    "dashboard:read",
    "capture:read",
    "capture:write",
    "ml:read",
  },
  UserRole.VIEWER: {
    "users:read",
    "policies:read",
    "firewall:read",
    "threats:read",
    "alerts:read",
    "incidents:read",
    "network:read",
    "devices:read",
    "trust:read",
    "audit:read",
    "dashboard:read",
    "capture:read",
    "ml:read",
  },
}


def extract_bearer_token(authorization_header: Optional[str]) -> Optional[str]:
  if not authorization_header:
    return None

  parts = authorization_header.split()

  if len(parts) != 2:
    return None

  scheme, token = parts

  if scheme.lower() != "bearer":
    return None

  return token


async def get_user_by_id(user_id: str) -> Optional[UserInDB]:
  if not ObjectId.is_valid(user_id):
    return None

  users_collection = get_users_collection()
  document = await users_collection.find_one({"_id": ObjectId(user_id)})
  return UserDocument.from_mongo(document)


async def get_user_by_email(email: str) -> Optional[UserInDB]:
  users_collection = get_users_collection()
  document = await users_collection.find_one({"email": email.lower()})
  return UserDocument.from_mongo(document)


async def get_user_by_username(username: str) -> Optional[UserInDB]:
  users_collection = get_users_collection()
  document = await users_collection.find_one({"username": username.lower()})
  return UserDocument.from_mongo(document)


async def get_user_document_by_email(email: str) -> Optional[dict]:
  users_collection = get_users_collection()
  return await users_collection.find_one({"email": email.lower()})


async def authenticate_user(email: str, password: str) -> Optional[UserInDB]:
  user_document = await get_user_document_by_email(email)

  if user_document is None:
    return None

  if not verify_password(password, user_document.get("hashed_password", "")):
    return None

  user = UserDocument.from_mongo(user_document)

  if user is None or not user.is_active:
    return None

  return user


async def update_last_login(user_id: str) -> None:
  if not ObjectId.is_valid(user_id):
    return

  users_collection = get_users_collection()
  await users_collection.update_one(
    {"_id": ObjectId(user_id)},
    {
      "$set": {
        "last_login_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
      }
    },
  )


def create_token_pair(user: UserInDB) -> dict[str, str]:
  access_token = create_access_token(
    user_id=str(user.id),
    email=user.email,
    username=user.username,
    role=user.role.value,
  )
  refresh_token = create_refresh_token(
    user_id=str(user.id),
    email=user.email,
    username=user.username,
    role=user.role.value,
  )

  return {
    "access_token": access_token,
    "refresh_token": refresh_token,
    "token_type": "bearer",
  }


def decode_access_token(token: str) -> TokenData:
  try:
    payload = verify_access_token(token)
    return TokenData(payload)
  except ValueError as exc:
    raise AuthenticationError(str(exc)) from exc


async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> UserPublic:
  credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
  )

  if token is None:
    raise credentials_exception

  try:
    token_data = decode_access_token(token)
  except AuthenticationError as exc:
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail=exc.message,
      headers={"WWW-Authenticate": "Bearer"},
    ) from exc

  from services.session_service import session_service

  if await session_service.is_token_revoked(token_data.jti):
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Token has been revoked",
      headers={"WWW-Authenticate": "Bearer"},
    )

  user = await get_user_by_id(token_data.user_id)

  if user is None:
    raise credentials_exception

  return UserDocument.to_public(user)


async def get_current_active_user(
  current_user: UserPublic = Depends(get_current_user),
) -> UserPublic:
  if not current_user.is_active:
    raise HTTPException(
      status_code=status.HTTP_403_FORBIDDEN,
      detail="Inactive user account",
    )

  return current_user


def has_permission(user: UserPublic, permission: str) -> bool:
  role_permissions = ROLE_PERMISSIONS.get(user.role, set())
  return permission in role_permissions


def require_roles(*allowed_roles: UserRole) -> Callable:
  allowed_role_values = {role.value for role in allowed_roles}

  async def role_checker(
    current_user: UserPublic = Depends(get_current_active_user),
  ) -> UserPublic:
    if current_user.role.value not in allowed_role_values:
      raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="You do not have permission to perform this action",
      )
    return current_user

  return role_checker


def require_permission(permission: str) -> Callable:
  async def permission_checker(
    current_user: UserPublic = Depends(get_current_active_user),
  ) -> UserPublic:
    if not has_permission(current_user, permission):
      raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Missing required permission: {permission}",
      )
    return current_user

  return permission_checker


async def require_network_ingest(
  request: Request,
  token: Optional[str] = Depends(oauth2_scheme),
) -> None:
  """Allow AI engine flow ingest via internal API key, JWT, or dev sender UA."""
  internal_key = request.headers.get("X-Internal-Api-Key")
  if settings.internal_api_key and internal_key == settings.internal_api_key:
    return

  if token:
    try:
      current_user = await get_current_user(token)
      if has_permission(current_user, "network:write"):
        return
    except HTTPException:
      pass

  user_agent = request.headers.get("User-Agent", "")
  if settings.is_development and user_agent.startswith("AI-NGFW-FeatureSender"):
    return

  raise HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Network flow ingest requires authentication",
    headers={"WWW-Authenticate": "Bearer"},
  )
