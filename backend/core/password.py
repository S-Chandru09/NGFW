from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain_password: str) -> str:
  if not plain_password:
    raise ValueError("Password cannot be empty")

  if len(plain_password) < 8:
    raise ValueError("Password must be at least 8 characters long")

  return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
  if not plain_password or not hashed_password:
    return False

  return pwd_context.verify(plain_password, hashed_password)
