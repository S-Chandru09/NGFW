from fastapi import APIRouter

from api.routes.analytics import router as analytics_router
from api.routes.auth import router as auth_router
from api.routes.dashboard import router as dashboard_router
from api.routes.devices import router as devices_router
from api.routes.firewall_engine import router as firewall_engine_router
from api.routes.firewall_rules import router as firewall_rules_router
from api.routes.incident_response import router as incident_response_router
from api.routes.ioc_database import router as ioc_database_router
from api.routes.live_capture import router as live_capture_router
from api.routes.logs import router as logs_router
from api.routes.network_flows import router as network_flows_router
from api.routes.network_graph import router as network_graph_router
from api.routes.packet_upload import router as packet_upload_router
from api.routes.threat_intelligence import router as threat_intelligence_router
from api.routes.stix_taxii import management_router as stix_taxii_management_router
from api.routes.stix_taxii import taxii_router as stix_taxii_router
from api.routes.trust_score import router as trust_score_router
from api.routes.users import router as users_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(devices_router)
api_router.include_router(analytics_router)
api_router.include_router(dashboard_router)
api_router.include_router(logs_router)
api_router.include_router(firewall_rules_router)
api_router.include_router(firewall_engine_router)
api_router.include_router(threat_intelligence_router)
api_router.include_router(ioc_database_router)
api_router.include_router(incident_response_router)
api_router.include_router(stix_taxii_router)
api_router.include_router(stix_taxii_management_router)
api_router.include_router(trust_score_router)
api_router.include_router(network_flows_router)
api_router.include_router(network_graph_router)
api_router.include_router(packet_upload_router)
api_router.include_router(live_capture_router)

__all__ = ["api_router"]
