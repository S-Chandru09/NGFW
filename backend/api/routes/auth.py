import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import ValidationError
from pymongo.errors import DuplicateKeyError

from core.auth_utils import (
  authenticate_user,
  create_token_pair,
  get_current_active_user,
  get_user_by_email,
  get_user_by_username,
  update_last_login,
)
from core.jwt_handler import (
  create_access_token,
  get_token_expiry_seconds,
  verify_refresh_token,
)
from core.password import hash_password
from database import get_users_collection
from models.user import UserCreate, UserDocument, UserPublic, UserRole
from services.session_service import session_service
from schemas.auth import (
  AuthResponse,
  LoginRequest,
  MessageResponse,
  OAuth2TokenResponse,
  ProtectedRouteResponse,
  RefreshTokenRequest,
  RegisterRequest,
  TokenResponse,
  UserProfileResponse,
)

logger = logging.getLogger("ai-ngfw.auth")

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _build_token_response(tokens: dict[str, str]) -> TokenResponse:
  return TokenResponse(
    access_token=tokens["access_token"],
    refresh_token=tokens["refresh_token"],
    token_type=tokens["token_type"],
    expires_in=get_token_expiry_seconds("access"),
  )


@router.post(
  "/register",
  response_model=AuthResponse,
  status_code=status.HTTP_201_CREATED,
  summary="Register a new user",
)
async def register_user(payload: RegisterRequest, request: Request) -> AuthResponse:
  try:
    user_data = UserCreate(
      email=payload.email,
      username=payload.username,
      full_name=payload.full_name,
      password=payload.password,
      role=UserRole.VIEWER,
      is_active=True,
    )
  except ValidationError as exc:
    raise RequestValidationError(exc.errors()) from exc

  user_data = user_data.model_copy(update={"role": UserRole.VIEWER, "is_active": True})

  existing_email = await get_user_by_email(user_data.email)
  if existing_email is not None:
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
      detail="Email is already registered",
    )

  existing_username = await get_user_by_username(user_data.username)
  if existing_username is not None:
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
      detail="Username is already taken",
    )

  hashed_password = hash_password(user_data.password)
  user_document = UserDocument.create_document(user_data, hashed_password)
  users_collection = get_users_collection()

  try:
    insert_result = await users_collection.insert_one(user_document)
  except DuplicateKeyError as exc:
    logger.warning("Duplicate user registration attempt: %s", exc)
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
      detail="User with this email or username already exists",
    ) from exc

  created_document = await users_collection.find_one({"_id": insert_result.inserted_id})
  created_user = UserDocument.from_mongo(created_document)

  if created_user is None:
    raise HTTPException(
      status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
      detail="Failed to create user account",
    )

  tokens = create_token_pair(created_user)

  client_ip = request.client.host if request.client else None
  user_agent = request.headers.get("user-agent")

  await session_service.register_session_from_tokens(
    user_id=str(created_user.id),
    username=created_user.username,
    access_token=tokens["access_token"],
    refresh_token=tokens["refresh_token"],
    ip_address=client_ip,
    user_agent=user_agent,
  )

  return AuthResponse(
    success=True,
    message="User registered successfully",
    user=UserDocument.to_public(created_user),
    tokens=_build_token_response(tokens),
  )


@router.post(
  "/login",
  response_model=AuthResponse,
  summary="Login with email and password",
)
async def login_user(login_data: LoginRequest, request: Request) -> AuthResponse:
  user = await authenticate_user(login_data.email, login_data.password)

  if user is None:
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Incorrect email or password",
      headers={"WWW-Authenticate": "Bearer"},
    )

  await update_last_login(str(user.id))
  tokens = create_token_pair(user)

  client_ip = request.client.host if request.client else None
  user_agent = request.headers.get("user-agent")

  await session_service.register_session_from_tokens(
    user_id=str(user.id),
    username=user.username,
    access_token=tokens["access_token"],
    refresh_token=tokens["refresh_token"],
    ip_address=client_ip,
    user_agent=user_agent,
  )

  return AuthResponse(
    success=True,
    message="Login successful",
    user=UserDocument.to_public(user),
    tokens=_build_token_response(tokens),
  )


@router.post(
  "/login/form",
  response_model=OAuth2TokenResponse,
  summary="Login using OAuth2 password form (Swagger compatible)",
)
async def login_user_form(
  request: Request,
  form_data: OAuth2PasswordRequestForm = Depends(),
) -> OAuth2TokenResponse:
  user = await authenticate_user(form_data.username, form_data.password)

  if user is None:
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Incorrect email or password",
      headers={"WWW-Authenticate": "Bearer"},
    )

  await update_last_login(str(user.id))
  tokens = create_token_pair(user)

  client_ip = request.client.host if request.client else None
  user_agent = request.headers.get("user-agent")

  await session_service.register_session_from_tokens(
    user_id=str(user.id),
    username=user.username,
    access_token=tokens["access_token"],
    refresh_token=tokens["refresh_token"],
    ip_address=client_ip,
    user_agent=user_agent,
  )

  return OAuth2TokenResponse(
    access_token=tokens["access_token"],
    token_type=tokens["token_type"],
  )


@router.post(
  "/refresh",
  response_model=TokenResponse,
  summary="Refresh access token using refresh token",
)
async def refresh_access_token(token_data: RefreshTokenRequest) -> TokenResponse:
  try:
    payload = verify_refresh_token(token_data.refresh_token)
  except ValueError as exc:
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail=str(exc),
      headers={"WWW-Authenticate": "Bearer"},
    ) from exc

  access_token = create_access_token(
    user_id=payload.sub,
    email=payload.email,
    username=payload.username,
    role=payload.role,
  )

  return TokenResponse(
    access_token=access_token,
    refresh_token=token_data.refresh_token,
    token_type="bearer",
    expires_in=get_token_expiry_seconds("access"),
  )


@router.get(
  "/me",
  response_model=UserProfileResponse,
  summary="Get current authenticated user profile",
)
async def get_current_user_profile(
  current_user: UserPublic = Depends(get_current_active_user),
) -> UserProfileResponse:
  return UserProfileResponse(
    success=True,
    message="Authenticated user profile retrieved successfully",
    user=current_user,
  )


@router.get(
  "/protected-example",
  response_model=ProtectedRouteResponse,
  summary="Protected route example requiring JWT authentication",
)
async def protected_route_example(
  current_user: UserPublic = Depends(get_current_active_user),
) -> ProtectedRouteResponse:
  role_permissions = {
    UserRole.ADMIN: ["full_system_access", "user_management", "policy_management"],
    UserRole.ANALYST: ["threat_analysis", "firewall_management", "network_monitoring"],
    UserRole.VIEWER: ["read_only_dashboard", "read_only_alerts"],
  }

  permissions = role_permissions.get(current_user.role, ["read_only_dashboard"])

  return ProtectedRouteResponse(
    success=True,
    message="You have successfully accessed a protected route",
    user=current_user,
    access_level=current_user.role.value,
    permissions=permissions,
    route="/api/v1/auth/protected-example",
    note="This endpoint demonstrates JWT Bearer token authentication for Zero Trust access control",
  )


@router.post(
  "/logout",
  response_model=MessageResponse,
  summary="Logout current user (client should discard tokens)",
)
async def logout_user(
  request: Request,
  current_user: UserPublic = Depends(get_current_active_user),
) -> MessageResponse:
  authorization = request.headers.get("authorization")
  token = authorization.split(" ", 1)[1] if authorization and " " in authorization else None

  if token:
    from core.jwt_handler import decode_token
    from database import get_sessions_collection

    try:
      payload = decode_token(token)
    except ValueError:
      payload = None

    if payload:
      session = await get_sessions_collection().find_one({
        "access_jti": payload["jti"],
        "is_active": True,
      })

      if session:
        await session_service.revoke_session(
          session,
          revoked_by=current_user.id,
          reason="User logout",
        )

  logger.info("User logged out: %s (%s)", current_user.email, current_user.id)

  return MessageResponse(
    success=True,
    message="Logout successful. Please discard access and refresh tokens on the client.",
  )
