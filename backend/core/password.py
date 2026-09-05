import bcrypt


def hash_password(plain_password: str) -> str:
  if not plain_password:
    raise ValueError("Password cannot be empty")

  if len(plain_password) < 8:
    raise ValueError("Password must be at least 8 characters long")

  hashed = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt())
  return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
  if not plain_password or not hashed_password:
    return False

  try:
    return bcrypt.checkpw(
      plain_password.encode("utf-8"),
      hashed_password.encode("utf-8"),
    )
  except ValueError:
    return False
