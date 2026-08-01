from typing import Optional

from pydantic import BaseModel, EmailStr, Field

from models.user import UserPublic


class LoginRequest(BaseModel):
  email: EmailStr
  password: str = Field(..., min_length=8, max_length=128)


class RefreshTokenRequest(BaseModel):
  refresh_token: str = Field(..., min_length=10)


class TokenResponse(BaseModel):
  access_token: str
  refresh_token: str
  token_type: str = "bearer"
  expires_in: int


class AuthResponse(BaseModel):
  success: bool = True
  message: str
  user: UserPublic
  tokens: TokenResponse


class MessageResponse(BaseModel):
  success: bool = True
  message: str


class UserProfileResponse(BaseModel):
  success: bool = True
  message: str
  user: UserPublic


class ProtectedRouteResponse(BaseModel):
  success: bool = True
  message: str
  user: UserPublic
  access_level: str
  permissions: list[str]
  route: str
  note: Optional[str] = None
