from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from models.user import UserPublic


class RegisterRequest(BaseModel):
  """Public signup payload. Role is never accepted from the client."""

  model_config = ConfigDict(extra="ignore")

  email: EmailStr
  username: str = Field(..., min_length=3, max_length=50)
  full_name: str = Field(..., min_length=2, max_length=100)
  password: str = Field(..., min_length=8, max_length=128)


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


class OAuth2TokenResponse(BaseModel):
  access_token: str
  token_type: str = "bearer"


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
