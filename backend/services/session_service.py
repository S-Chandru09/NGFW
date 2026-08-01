from datetime import datetime, timezone
from typing import Any, Optional

from core.jwt_handler import decode_token
from database import get_revoked_tokens_collection, get_sessions_collection


class SessionService:
  def _utc_now(self) -> datetime:
    return datetime.now(timezone.utc)

  def _extract_jti(self, token: str) -> str:
    payload = decode_token(token)
    return payload["jti"]

  def _extract_expiry(self, token: str) -> datetime:
    payload = decode_token(token)
    return datetime.fromtimestamp(payload["exp"], tz=timezone.utc)

  async def is_token_revoked(self, jti: str) -> bool:
    revoked = get_revoked_tokens_collection()
    document = await revoked.find_one({"jti": jti})
    return document is not None

  async def register_session_from_tokens(
    self,
    user_id: str,
    username: str,
    access_token: str,
    refresh_token: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
  ) -> dict[str, Any]:
    from models.incident_response import SessionDocument

    access_jti = self._extract_jti(access_token)
    refresh_jti = self._extract_jti(refresh_token)
    expires_at = self._extract_expiry(refresh_token)

    session_document = SessionDocument.create_document(
      user_id=user_id,
      username=username,
      access_jti=access_jti,
      refresh_jti=refresh_jti,
      expires_at=expires_at,
      ip_address=ip_address,
      user_agent=user_agent,
    )

    sessions = get_sessions_collection()
    await sessions.insert_one(session_document)
    return session_document

  async def _revoke_jti(
    self,
    jti: str,
    token_type: str,
    user_id: str,
    revoked_by: str,
    reason: str,
    session_id: Optional[str] = None,
    expires_at: Optional[datetime] = None,
  ) -> None:
    revoked = get_revoked_tokens_collection()
    existing = await revoked.find_one({"jti": jti})

    if existing is not None:
      return

    await revoked.insert_one({
      "jti": jti,
      "token_type": token_type,
      "user_id": user_id,
      "session_id": session_id,
      "revoked_at": self._utc_now(),
      "revoked_by": revoked_by,
      "reason": reason,
      "expires_at": expires_at or self._utc_now(),
    })

  async def revoke_session(
    self,
    session: dict[str, Any],
    revoked_by: str,
    reason: str,
  ) -> int:
    if not session.get("is_active", False):
      return 0

    sessions = get_sessions_collection()
    now = self._utc_now()
    revoked_count = 0

    for token_type, jti_key in [("access", "access_jti"), ("refresh", "refresh_jti")]:
      jti = session.get(jti_key)
      if jti:
        await self._revoke_jti(
          jti=jti,
          token_type=token_type,
          user_id=session["user_id"],
          revoked_by=revoked_by,
          reason=reason,
          session_id=session.get("session_id"),
          expires_at=session.get("expires_at"),
        )
        revoked_count += 1

    await sessions.update_one(
      {"session_id": session["session_id"]},
      {
        "$set": {
          "is_active": False,
          "revoked_at": now,
          "revoked_by": revoked_by,
          "revoked_reason": reason,
        }
      },
    )

    return revoked_count

  async def kill_sessions(
    self,
    revoked_by: str,
    reason: str,
    session_id: Optional[str] = None,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    kill_all_for_user: bool = False,
  ) -> tuple[list[str], int]:
    sessions = get_sessions_collection()
    query: dict[str, Any] = {"is_active": True}

    if session_id:
      query["session_id"] = session_id
    elif user_id and kill_all_for_user:
      query["user_id"] = user_id
    elif user_id:
      query["user_id"] = user_id
    elif ip_address:
      query["ip_address"] = ip_address
    else:
      return [], 0

    matched_sessions = [document async for document in sessions.find(query)]
    killed_session_ids: list[str] = []
    total_revoked = 0

    for session in matched_sessions:
      revoked_count = await self.revoke_session(session, revoked_by, reason)
      if revoked_count > 0:
        killed_session_ids.append(session["session_id"])
        total_revoked += revoked_count

    return killed_session_ids, total_revoked

  async def list_active_sessions(
    self,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    limit: int = 50,
  ) -> list[dict[str, Any]]:
    sessions = get_sessions_collection()
    query: dict[str, Any] = {"is_active": True}

    if user_id:
      query["user_id"] = user_id

    if ip_address:
      query["ip_address"] = ip_address

    cursor = sessions.find(query).sort("created_at", -1).limit(limit)
    return [document async for document in cursor]


session_service = SessionService()
