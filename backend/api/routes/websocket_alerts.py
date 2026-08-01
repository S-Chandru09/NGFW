import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from core.auth_utils import ROLE_PERMISSIONS, TokenData, verify_access_token
from core.websocket_manager import websocket_manager
from models.user import UserRole

logger = logging.getLogger("ai-ngfw.websocket_route")

router = APIRouter()


def _user_can_receive_alerts(role: UserRole) -> bool:
  permissions = ROLE_PERMISSIONS.get(role, set())
  return "alerts:read" in permissions or "dashboard:read" in permissions


@router.websocket("/ws")
async def threat_alert_socket(websocket: WebSocket, token: str = Query(...)) -> None:
  try:
    payload = verify_access_token(token)
    token_data = TokenData(payload)
  except ValueError as exc:
    await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid access token")
    logger.warning("WebSocket rejected: invalid token (%s)", exc)
    return

  if not _user_can_receive_alerts(token_data.role):
    await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Missing alert permissions")
    logger.warning("WebSocket rejected: missing permissions for user=%s", token_data.email)
    return

  await websocket_manager.connect(websocket)

  try:
    await websocket_manager.send_connection_ack(websocket)

    while True:
      message = await websocket.receive_text()
      if message.strip().lower() == "ping":
        await websocket.send_text('{"type":"pong","data":{"message":"pong"}}')
  except WebSocketDisconnect:
    pass
  except Exception as exc:
    logger.warning("WebSocket session ended with error for user=%s: %s", token_data.email, exc)
  finally:
    await websocket_manager.disconnect(websocket)
