import logging
from typing import Any, Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING, TEXT, IndexModel
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

from config import settings

logger = logging.getLogger("ai-ngfw.database")


class CollectionNames:
  USERS = "users"
  DEVICES = "devices"
  POLICIES = "policies"
  FIREWALL_RULES = "firewall_rules"
  NETWORK_FLOWS = "network_flows"
  THREAT_ALERTS = "threat_alerts"
  IOC_INDICATORS = "ioc_indicators"
  PACKET_UPLOADS = "packet_uploads"
  AUDIT_LOGS = "audit_logs"
  SESSIONS = "sessions"
  BEHAVIOUR_EVENTS = "behaviour_events"
  TRUST_SCORES = "trust_scores"
  TAXII_COLLECTIONS = "taxii_collections"
  STIX_OBJECTS = "stix_objects"
  INCIDENTS = "incidents"
  INCIDENT_REPORTS = "incident_reports"
  REVOKED_TOKENS = "revoked_tokens"


COLLECTION_INDEXES: dict[str, list[IndexModel]] = {
  CollectionNames.USERS: [
    IndexModel([("email", ASCENDING)], unique=True, name="users_email_unique"),
    IndexModel([("username", ASCENDING)], unique=True, name="users_username_unique"),
    IndexModel([("role", ASCENDING)], name="users_role_index"),
    IndexModel([("is_active", ASCENDING)], name="users_is_active_index"),
    IndexModel([("created_at", DESCENDING)], name="users_created_at_index"),
  ],
  CollectionNames.DEVICES: [
    IndexModel([("device_id", ASCENDING)], unique=True, name="devices_device_id_unique"),
    IndexModel([("user_id", ASCENDING)], name="devices_user_id_index"),
    IndexModel([("trust_score", DESCENDING)], name="devices_trust_score_index"),
    IndexModel([("is_trusted", ASCENDING)], name="devices_is_trusted_index"),
    IndexModel([("last_seen_at", DESCENDING)], name="devices_last_seen_at_index"),
    IndexModel(
      [("ip_address", ASCENDING)],
      unique=True,
      name="devices_ip_address_unique",
      partialFilterExpression={"ip_address": {"$type": "string"}},
    ),
  ],
  CollectionNames.POLICIES: [
    IndexModel([("name", ASCENDING)], unique=True, name="policies_name_unique"),
    IndexModel([("is_active", ASCENDING)], name="policies_is_active_index"),
    IndexModel([("priority", DESCENDING)], name="policies_priority_index"),
    IndexModel([("created_at", DESCENDING)], name="policies_created_at_index"),
  ],
  CollectionNames.FIREWALL_RULES: [
    IndexModel([("rule_id", ASCENDING)], unique=True, name="firewall_rules_rule_id_unique"),
    IndexModel([("name", ASCENDING)], unique=True, name="firewall_rules_name_unique"),
    IndexModel([("action", ASCENDING)], name="firewall_rules_action_index"),
    IndexModel([("protocol", ASCENDING)], name="firewall_rules_protocol_index"),
    IndexModel([("is_enabled", ASCENDING)], name="firewall_rules_is_enabled_index"),
    IndexModel([("is_expired", ASCENDING)], name="firewall_rules_is_expired_index"),
    IndexModel([("priority", DESCENDING)], name="firewall_rules_priority_index"),
    IndexModel([("source_ip", ASCENDING)], name="firewall_rules_source_ip_index"),
    IndexModel([("destination_ip", ASCENDING)], name="firewall_rules_destination_ip_index"),
    IndexModel([("expires_at", ASCENDING)], name="firewall_rules_expires_at_index"),
    IndexModel([("created_at", DESCENDING)], name="firewall_rules_created_at_index"),
    IndexModel([("source_country", ASCENDING)], name="firewall_rules_source_country_index"),
    IndexModel([("destination_country", ASCENDING)], name="firewall_rules_destination_country_index"),
    IndexModel([("is_automatic", ASCENDING)], name="firewall_rules_is_automatic_index"),
    IndexModel([("trigger_source", ASCENDING)], name="firewall_rules_trigger_source_index"),
  ],
  CollectionNames.NETWORK_FLOWS: [
    IndexModel([("flow_id", ASCENDING)], unique=True, name="network_flows_flow_id_unique"),
    IndexModel([("source_ip", ASCENDING)], name="network_flows_source_ip_index"),
    IndexModel([("destination_ip", ASCENDING)], name="network_flows_destination_ip_index"),
    IndexModel([("protocol", ASCENDING)], name="network_flows_protocol_index"),
    IndexModel([("is_threat", ASCENDING)], name="network_flows_is_threat_index"),
    IndexModel([("captured_at", DESCENDING)], name="network_flows_captured_at_index"),
  ],
  CollectionNames.THREAT_ALERTS: [
    IndexModel([("alert_id", ASCENDING)], unique=True, name="threat_alerts_alert_id_unique"),
    IndexModel([("severity", ASCENDING)], name="threat_alerts_severity_index"),
    IndexModel([("status", ASCENDING)], name="threat_alerts_status_index"),
    IndexModel([("threat_type", ASCENDING)], name="threat_alerts_threat_type_index"),
    IndexModel([("source_ip", ASCENDING)], name="threat_alerts_source_ip_index"),
    IndexModel([("detected_at", DESCENDING)], name="threat_alerts_detected_at_index"),
  ],
  CollectionNames.IOC_INDICATORS: [
    IndexModel([("ioc_id", ASCENDING)], unique=True, name="ioc_indicators_ioc_id_unique"),
    IndexModel([("value_hash", ASCENDING)], unique=True, name="ioc_indicators_value_hash_unique"),
    IndexModel([("ioc_type", ASCENDING)], name="ioc_indicators_ioc_type_index"),
    IndexModel([("value", ASCENDING)], name="ioc_indicators_value_index"),
    IndexModel([("hash_type", ASCENDING)], name="ioc_indicators_hash_type_index"),
    IndexModel([("threat_level", ASCENDING)], name="ioc_indicators_threat_level_index"),
    IndexModel([("reputation_score", DESCENDING)], name="ioc_indicators_reputation_score_index"),
    IndexModel([("is_malicious", ASCENDING)], name="ioc_indicators_is_malicious_index"),
    IndexModel([("is_active", ASCENDING)], name="ioc_indicators_is_active_index"),
    IndexModel([("source", ASCENDING)], name="ioc_indicators_source_index"),
    IndexModel([("country", ASCENDING)], name="ioc_indicators_country_index"),
    IndexModel([("threat_categories", ASCENDING)], name="ioc_indicators_threat_categories_index"),
    IndexModel([("tags", ASCENDING)], name="ioc_indicators_tags_index"),
    IndexModel([("last_seen_at", DESCENDING)], name="ioc_indicators_last_seen_at_index"),
    IndexModel([("created_at", DESCENDING)], name="ioc_indicators_created_at_index"),
    IndexModel(
      [("value", TEXT), ("description", TEXT), ("source", TEXT), ("country", TEXT)],
      name="ioc_indicators_text_search",
    ),
  ],
  CollectionNames.AUDIT_LOGS: [
    IndexModel([("log_id", ASCENDING)], unique=True, name="audit_logs_log_id_unique"),
    IndexModel([("event_type", ASCENDING)], name="audit_logs_event_type_index"),
    IndexModel([("severity", ASCENDING)], name="audit_logs_severity_index"),
    IndexModel([("user_id", ASCENDING)], name="audit_logs_user_id_index"),
    IndexModel([("username", ASCENDING)], name="audit_logs_username_index"),
    IndexModel([("ip_address", ASCENDING)], name="audit_logs_ip_address_index"),
    IndexModel([("source", ASCENDING)], name="audit_logs_source_index"),
    IndexModel([("resource_type", ASCENDING)], name="audit_logs_resource_type_index"),
    IndexModel([("resource_id", ASCENDING)], name="audit_logs_resource_id_index"),
    IndexModel([("created_at", DESCENDING)], name="audit_logs_created_at_index"),
    IndexModel(
      [("message", TEXT), ("description", TEXT), ("username", TEXT), ("source", TEXT)],
      name="audit_logs_text_search",
    ),
  ],
  CollectionNames.PACKET_UPLOADS: [
    IndexModel([("upload_id", ASCENDING)], unique=True, name="packet_uploads_upload_id_unique"),
    IndexModel([("file_hash", ASCENDING)], name="packet_uploads_file_hash_index"),
    IndexModel([("status", ASCENDING)], name="packet_uploads_status_index"),
    IndexModel([("ai_engine_status", ASCENDING)], name="packet_uploads_ai_engine_status_index"),
    IndexModel([("ai_engine_job_id", ASCENDING)], name="packet_uploads_ai_engine_job_id_index"),
    IndexModel([("uploaded_by", ASCENDING)], name="packet_uploads_uploaded_by_index"),
    IndexModel([("created_at", DESCENDING)], name="packet_uploads_created_at_index"),
  ],
  CollectionNames.SESSIONS: [
    IndexModel([("session_id", ASCENDING)], unique=True, name="sessions_session_id_unique"),
    IndexModel([("user_id", ASCENDING)], name="sessions_user_id_index"),
    IndexModel([("device_id", ASCENDING)], name="sessions_device_id_index"),
    IndexModel([("is_active", ASCENDING)], name="sessions_is_active_index"),
    IndexModel([("expires_at", ASCENDING)], name="sessions_expires_at_index"),
  ],
  CollectionNames.BEHAVIOUR_EVENTS: [
    IndexModel([("event_id", ASCENDING)], unique=True, name="behaviour_events_event_id_unique"),
    IndexModel([("user_id", ASCENDING)], name="behaviour_events_user_id_index"),
    IndexModel([("device_id", ASCENDING)], name="behaviour_events_device_id_index"),
    IndexModel([("event_type", ASCENDING)], name="behaviour_events_event_type_index"),
    IndexModel([("risk_level", ASCENDING)], name="behaviour_events_risk_level_index"),
    IndexModel([("created_at", DESCENDING)], name="behaviour_events_created_at_index"),
  ],
  CollectionNames.TRUST_SCORES: [
    IndexModel([("score_id", ASCENDING)], unique=True, name="trust_scores_score_id_unique"),
    IndexModel([("user_id", ASCENDING)], name="trust_scores_user_id_index"),
    IndexModel([("device_id", ASCENDING)], name="trust_scores_device_id_index"),
    IndexModel([("composite_score", DESCENDING)], name="trust_scores_composite_score_index"),
    IndexModel([("trust_level", ASCENDING)], name="trust_scores_trust_level_index"),
    IndexModel([("is_access_allowed", ASCENDING)], name="trust_scores_is_access_allowed_index"),
    IndexModel([("calculated_at", DESCENDING)], name="trust_scores_calculated_at_index"),
    IndexModel(
      [("user_id", ASCENDING), ("device_id", ASCENDING)],
      name="trust_scores_user_device_index",
    ),
  ],
  CollectionNames.TAXII_COLLECTIONS: [
    IndexModel([("collection_id", ASCENDING)], unique=True, name="taxii_collections_id_unique"),
    IndexModel([("title", ASCENDING)], name="taxii_collections_title_index"),
    IndexModel([("is_active", ASCENDING)], name="taxii_collections_is_active_index"),
    IndexModel([("updated_at", DESCENDING)], name="taxii_collections_updated_at_index"),
  ],
  CollectionNames.STIX_OBJECTS: [
    IndexModel([("stix_id", ASCENDING)], unique=True, name="stix_objects_stix_id_unique"),
    IndexModel([("collection_id", ASCENDING)], name="stix_objects_collection_id_index"),
    IndexModel([("object_type", ASCENDING)], name="stix_objects_object_type_index"),
    IndexModel([("modified", DESCENDING)], name="stix_objects_modified_index"),
    IndexModel([("source_ioc_id", ASCENDING)], name="stix_objects_source_ioc_id_index"),
  ],
  CollectionNames.INCIDENTS: [
    IndexModel([("incident_id", ASCENDING)], unique=True, name="incidents_incident_id_unique"),
    IndexModel([("status", ASCENDING)], name="incidents_status_index"),
    IndexModel([("severity", ASCENDING)], name="incidents_severity_index"),
    IndexModel([("source_ip", ASCENDING)], name="incidents_source_ip_index"),
    IndexModel([("affected_user_id", ASCENDING)], name="incidents_affected_user_id_index"),
    IndexModel([("assigned_to", ASCENDING)], name="incidents_assigned_to_index"),
    IndexModel([("detected_at", DESCENDING)], name="incidents_detected_at_index"),
    IndexModel([("created_at", DESCENDING)], name="incidents_created_at_index"),
  ],
  CollectionNames.INCIDENT_REPORTS: [
    IndexModel([("report_id", ASCENDING)], unique=True, name="incident_reports_report_id_unique"),
    IndexModel([("incident_id", ASCENDING)], name="incident_reports_incident_id_index"),
    IndexModel([("generated_at", DESCENDING)], name="incident_reports_generated_at_index"),
  ],
  CollectionNames.REVOKED_TOKENS: [
    IndexModel([("jti", ASCENDING)], unique=True, name="revoked_tokens_jti_unique"),
    IndexModel([("user_id", ASCENDING)], name="revoked_tokens_user_id_index"),
    IndexModel([("session_id", ASCENDING)], name="revoked_tokens_session_id_index"),
    IndexModel([("expires_at", ASCENDING)], expireAfterSeconds=0, name="revoked_tokens_ttl_index"),
  ],
}


class MongoDBManager:
  def __init__(self) -> None:
    self._client: Optional[AsyncIOMotorClient] = None
    self._database: Optional[AsyncIOMotorDatabase] = None
    self._is_connected: bool = False

  @property
  def client(self) -> Optional[AsyncIOMotorClient]:
    return self._client

  @property
  def database(self) -> Optional[AsyncIOMotorDatabase]:
    return self._database

  @property
  def is_connected(self) -> bool:
    return self._is_connected

  def _build_client_options(self) -> dict[str, Any]:
    return {
      "minPoolSize": settings.mongodb_min_pool_size,
      "maxPoolSize": settings.mongodb_max_pool_size,
      "serverSelectionTimeoutMS": 5000,
      "connectTimeoutMS": 10000,
      "socketTimeoutMS": 20000,
      "retryWrites": True,
      "retryReads": True,
    }

  async def connect(self) -> None:
    if self._is_connected and self._client is not None and self._database is not None:
      logger.info("MongoDB is already connected")
      return

    logger.info(
      "Connecting to MongoDB | url=%s | database=%s | min_pool=%s | max_pool=%s",
      settings.mongodb_url,
      settings.mongodb_database,
      settings.mongodb_min_pool_size,
      settings.mongodb_max_pool_size,
    )

    try:
      self._client = AsyncIOMotorClient(
        settings.mongodb_connection_string,
        **self._build_client_options(),
      )
      self._database = self._client[settings.mongodb_database]
      await self._client.admin.command("ping")
      self._is_connected = True
      logger.info("MongoDB connected successfully to database: %s", settings.mongodb_database)
    except (ConnectionFailure, ServerSelectionTimeoutError) as exc:
      self._client = None
      self._database = None
      self._is_connected = False
      logger.error("MongoDB connection failed: %s", exc)
      raise
    except Exception as exc:
      self._client = None
      self._database = None
      self._is_connected = False
      logger.error("Unexpected MongoDB connection error: %s", exc)
      raise

  async def disconnect(self) -> None:
    if self._client is not None:
      self._client.close()
      logger.info("MongoDB connection closed")

    self._client = None
    self._database = None
    self._is_connected = False

  async def ping(self) -> bool:
    if self._client is None:
      return False

    try:
      await self._client.admin.command("ping")
      return True
    except Exception as exc:
      logger.warning("MongoDB ping failed: %s", exc)
      return False

  async def get_connection_status(self) -> dict[str, Any]:
    is_alive = await self.ping()

    status = {
      "connected": self._is_connected and is_alive,
      "database": settings.mongodb_database,
      "url": settings.mongodb_url,
      "min_pool_size": settings.mongodb_min_pool_size,
      "max_pool_size": settings.mongodb_max_pool_size,
    }

    if not is_alive:
      status["error"] = "MongoDB ping failed or client is not initialized"

    return status

  async def ensure_indexes(self) -> None:
    database = get_database()

    for collection_name, indexes in COLLECTION_INDEXES.items():
      collection = database[collection_name]
      result = await collection.create_indexes(indexes)
      logger.info("Indexes ensured for collection '%s': %s", collection_name, result)

  def get_database(self) -> AsyncIOMotorDatabase:
    if self._database is None:
      raise RuntimeError("MongoDB database is not initialized. Call connect() first.")
    return self._database

  def get_collection(self, collection_name: str) -> AsyncIOMotorCollection:
    database = self.get_database()
    return database[collection_name]


mongodb_manager = MongoDBManager()


async def connect_to_mongodb() -> None:
  await mongodb_manager.connect()
  await mongodb_manager.ensure_indexes()


async def close_mongodb_connection() -> None:
  await mongodb_manager.disconnect()


async def ping_database() -> bool:
  return await mongodb_manager.ping()


async def get_connection_status() -> dict[str, Any]:
  return await mongodb_manager.get_connection_status()


def get_client() -> AsyncIOMotorClient:
  client = mongodb_manager.client
  if client is None:
    raise RuntimeError("MongoDB client is not initialized. Call connect_to_mongodb() first.")
  return client


def get_database() -> AsyncIOMotorDatabase:
  return mongodb_manager.get_database()


def get_collection(collection_name: str) -> AsyncIOMotorCollection:
  return mongodb_manager.get_collection(collection_name)


def get_users_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.USERS)


def get_devices_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.DEVICES)


def get_policies_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.POLICIES)


def get_firewall_rules_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.FIREWALL_RULES)


def get_network_flows_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.NETWORK_FLOWS)


def get_threat_alerts_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.THREAT_ALERTS)


def get_ioc_indicators_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.IOC_INDICATORS)


def get_packet_uploads_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.PACKET_UPLOADS)


def get_audit_logs_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.AUDIT_LOGS)


def get_sessions_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.SESSIONS)


def get_behaviour_events_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.BEHAVIOUR_EVENTS)


def get_trust_scores_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.TRUST_SCORES)


def get_taxii_collections_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.TAXII_COLLECTIONS)


def get_stix_objects_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.STIX_OBJECTS)


def get_incidents_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.INCIDENTS)


def get_incident_reports_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.INCIDENT_REPORTS)


def get_revoked_tokens_collection() -> AsyncIOMotorCollection:
  return get_collection(CollectionNames.REVOKED_TOKENS)


async def get_db() -> AsyncIOMotorDatabase:
  return get_database()
