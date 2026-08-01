from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional

from bson import ObjectId
from pydantic import BaseModel, BeforeValidator, ConfigDict, EmailStr, Field, field_validator


class UserRole(str, Enum):
  ADMIN = "admin"
  ANALYST = "analyst"
  VIEWER = "viewer"


def validate_object_id(value: Any) -> str:
  if isinstance(value, ObjectId):
    return str(value)

  if isinstance(value, str) and ObjectId.is_valid(value):
    return value

  raise ValueError("Invalid ObjectId")


PyObjectId = Annotated[str, BeforeValidator(validate_object_id)]


class UserBase(BaseModel):
  email: EmailStr
  username: str = Field(..., min_length=3, max_length=50)
  full_name: str = Field(..., min_length=2, max_length=100)
  role: UserRole = UserRole.VIEWER
  is_active: bool = True

  @field_validator("username")
  @classmethod
  def validate_username(cls, value: str) -> str:
    cleaned = value.strip().lower()

    if not cleaned.replace("_", "").replace("-", "").isalnum():
      raise ValueError("Username can only contain letters, numbers, hyphens, and underscores")

    return cleaned


class UserCreate(UserBase):
  password: str = Field(..., min_length=8, max_length=128)

  @field_validator("password")
  @classmethod
  def validate_password_strength(cls, value: str) -> str:
    if not any(char.isupper() for char in value):
      raise ValueError("Password must contain at least one uppercase letter")

    if not any(char.islower() for char in value):
      raise ValueError("Password must contain at least one lowercase letter")

    if not any(char.isdigit() for char in value):
      raise ValueError("Password must contain at least one digit")

    return value


class UserUpdate(BaseModel):
  email: Optional[EmailStr] = None
  username: Optional[str] = Field(default=None, min_length=3, max_length=50)
  full_name: Optional[str] = Field(default=None, min_length=2, max_length=100)
  role: Optional[UserRole] = None
  is_active: Optional[bool] = None
  password: Optional[str] = Field(default=None, min_length=8, max_length=128)

  @field_validator("username")
  @classmethod
  def validate_username(cls, value: Optional[str]) -> Optional[str]:
    if value is None:
      return value

    cleaned = value.strip().lower()

    if not cleaned.replace("_", "").replace("-", "").isalnum():
      raise ValueError("Username can only contain letters, numbers, hyphens, and underscores")

    return cleaned


class UserInDB(UserBase):
  model_config = ConfigDict(populate_by_name=True)

  id: PyObjectId = Field(alias="_id")
  hashed_password: str
  created_at: datetime
  updated_at: datetime
  last_login_at: Optional[datetime] = None


class UserPublic(BaseModel):
  model_config = ConfigDict(populate_by_name=True)

  id: PyObjectId = Field(alias="_id")
  email: EmailStr
  username: str
  full_name: str
  role: UserRole
  is_active: bool
  created_at: datetime
  updated_at: datetime
  last_login_at: Optional[datetime] = None


class UserDocument:
  @staticmethod
  def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

  @staticmethod
  def create_document(user_data: UserCreate, hashed_password: str) -> dict[str, Any]:
    now = UserDocument._utc_now()

    return {
      "email": user_data.email.lower(),
      "username": user_data.username,
      "full_name": user_data.full_name,
      "role": user_data.role.value,
      "is_active": user_data.is_active,
      "hashed_password": hashed_password,
      "created_at": now,
      "updated_at": now,
      "last_login_at": None,
    }

  @staticmethod
  def update_document(
    existing_user: dict[str, Any],
    update_data: UserUpdate,
    hashed_password: Optional[str] = None,
  ) -> dict[str, Any]:
    update_fields = update_data.model_dump(exclude_unset=True, exclude={"password"})

    if update_data.email is not None:
      update_fields["email"] = update_data.email.lower()

    if update_data.role is not None:
      update_fields["role"] = update_data.role.value

    if hashed_password is not None:
      update_fields["hashed_password"] = hashed_password

    update_fields["updated_at"] = UserDocument._utc_now()

    return {**existing_user, **update_fields}

  @staticmethod
  def from_mongo(document: Optional[dict[str, Any]]) -> Optional[UserInDB]:
    if document is None:
      return None

    document_copy = dict(document)
    document_copy["_id"] = str(document_copy["_id"])
    return UserInDB(**document_copy)

  @staticmethod
  def to_public(user: UserInDB) -> UserPublic:
    return UserPublic(
      _id=user.id,
      email=user.email,
      username=user.username,
      full_name=user.full_name,
      role=user.role,
      is_active=user.is_active,
      created_at=user.created_at,
      updated_at=user.updated_at,
      last_login_at=user.last_login_at,
    )

  @staticmethod
  def to_public_from_mongo(document: Optional[dict[str, Any]]) -> Optional[UserPublic]:
    user = UserDocument.from_mongo(document)
    if user is None:
      return None
    return UserDocument.to_public(user)
