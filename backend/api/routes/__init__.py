from api.routes.auth import router as auth_router
from api.routes.dashboard import router as dashboard_router
from api.routes.firewall_rules import router as firewall_rules_router
from api.routes.logs import router as logs_router
from api.routes.packet_upload import router as packet_upload_router
from api.routes.threat_intelligence import router as threat_intelligence_router

__all__ = [
  "auth_router",
  "dashboard_router",
  "logs_router",
  "firewall_rules_router",
  "threat_intelligence_router",
  "packet_upload_router",
]
