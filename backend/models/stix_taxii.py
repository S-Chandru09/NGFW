from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class StixObjectType(str, Enum):
  INDICATOR = "indicator"
  MALWARE = "malware"
  THREAT_ACTOR = "threat-actor"
  ATTACK_PATTERN = "attack-pattern"
  RELATIONSHIP = "relationship"
  IDENTITY = "identity"


STIX_SPEC_VERSION = "2.1"
TAXII_VERSION = "2.1"
API_ROOT_PATH = "/api/v1/taxii2/root"


def utc_now() -> datetime:
  return datetime.now(timezone.utc)


def generate_stix_id(object_type: str) -> str:
  return f"{object_type}--{uuid4()}"


def ioc_to_stix_pattern(ioc_type: str, value: str) -> str:
  if ioc_type == "ip":
    return f"[ipv4-addr:value = '{value}']"
  if ioc_type == "domain":
    return f"[domain-name:value = '{value}']"
  if ioc_type == "hash":
    return f"[file:hashes.'SHA-256' = '{value}']"
  if ioc_type == "url":
    return f"[url:value = '{value}']"
  return f"[x-ngfw-ioc:value = '{value}']"


DEFAULT_COLLECTIONS = [
  {
    "collection_id": "malicious-indicators",
    "title": "Malicious Indicators",
    "description": "STIX indicators derived from IP, domain, and hash IOCs",
    "media_types": ["application/vnd.oasis.stix+json; version=2.1"],
  },
  {
    "collection_id": "malware-families",
    "title": "Malware Families",
    "description": "Simulated malware family STIX objects",
    "media_types": ["application/vnd.oasis.stix+json; version=2.1"],
  },
  {
    "collection_id": "threat-actors",
    "title": "Threat Actors",
    "description": "Simulated threat actor profiles",
    "media_types": ["application/vnd.oasis.stix+json; version=2.1"],
  },
  {
    "collection_id": "attack-patterns",
    "title": "Attack Patterns",
    "description": "MITRE ATT&CK style attack pattern simulation",
    "media_types": ["application/vnd.oasis.stix+json; version=2.1"],
  },
]

SEED_MALWARE = [
  {"name": "Emotet", "labels": ["trojan", "banking"]},
  {"name": "WannaCry", "labels": ["ransomware", "worm"]},
  {"name": "Cobalt Strike", "labels": ["c2", "post-exploitation"]},
]

SEED_THREAT_ACTORS = [
  {"name": "APT29", "labels": ["nation-state", "espionage"]},
  {"name": "Lazarus Group", "labels": ["nation-state", "financial"]},
  {"name": "FIN7", "labels": ["cybercrime", "financial"]},
]

SEED_ATTACK_PATTERNS = [
  {"name": "Phishing", "external_id": "T1566"},
  {"name": "Command and Control", "external_id": "T1071"},
  {"name": "Data Exfiltration", "external_id": "T1041"},
  {"name": "Brute Force", "external_id": "T1110"},
]


class TaxiiCollectionDocument:
  @staticmethod
  def create_document(collection_data: dict[str, Any]) -> dict[str, Any]:
    now = utc_now()
    return {
      "collection_id": collection_data["collection_id"],
      "title": collection_data["title"],
      "description": collection_data["description"],
      "can_read": True,
      "can_write": False,
      "media_types": collection_data.get("media_types", []),
      "object_count": 0,
      "is_active": True,
      "last_synced_at": None,
      "created_at": now,
      "updated_at": now,
    }


class StixObjectDocument:
  @staticmethod
  def create_indicator_from_ioc(ioc: dict[str, Any], collection_id: str) -> dict[str, Any]:
    now = utc_now()
    object_type = StixObjectType.INDICATOR.value
    stix_id = generate_stix_id(object_type)
    pattern = ioc_to_stix_pattern(ioc.get("ioc_type", "ip"), ioc.get("value", ""))

    stix_payload = {
      "type": object_type,
      "spec_version": STIX_SPEC_VERSION,
      "id": stix_id,
      "created": now.isoformat(),
      "modified": now.isoformat(),
      "name": f"IOC {ioc.get('value')}",
      "description": ioc.get("description") or f"Indicator for {ioc.get('value')}",
      "pattern": pattern,
      "pattern_type": "stix",
      "valid_from": now.isoformat(),
      "labels": ["malicious-activity"] if ioc.get("is_malicious") else ["benign"],
      "confidence": ioc.get("reputation_score", 50),
      "x_threat_level": ioc.get("threat_level"),
      "x_source": ioc.get("source"),
    }

    return {
      "stix_id": stix_id,
      "collection_id": collection_id,
      "object_type": object_type,
      "name": stix_payload["name"],
      "stix_payload": stix_payload,
      "source_ioc_id": ioc.get("ioc_id"),
      "created_at": now,
      "modified": now,
    }

  @staticmethod
  def create_malware(name: str, labels: list[str], collection_id: str) -> dict[str, Any]:
    now = utc_now()
    object_type = StixObjectType.MALWARE.value
    stix_id = generate_stix_id(object_type)

    stix_payload = {
      "type": object_type,
      "spec_version": STIX_SPEC_VERSION,
      "id": stix_id,
      "created": now.isoformat(),
      "modified": now.isoformat(),
      "name": name,
      "is_family": True,
      "labels": labels,
      "malware_types": labels,
    }

    return {
      "stix_id": stix_id,
      "collection_id": collection_id,
      "object_type": object_type,
      "name": name,
      "stix_payload": stix_payload,
      "source_ioc_id": None,
      "created_at": now,
      "modified": now,
    }

  @staticmethod
  def create_threat_actor(name: str, labels: list[str], collection_id: str) -> dict[str, Any]:
    now = utc_now()
    object_type = StixObjectType.THREAT_ACTOR.value
    stix_id = generate_stix_id(object_type)

    stix_payload = {
      "type": object_type,
      "spec_version": STIX_SPEC_VERSION,
      "id": stix_id,
      "created": now.isoformat(),
      "modified": now.isoformat(),
      "name": name,
      "threat_actor_types": labels,
      "labels": labels,
    }

    return {
      "stix_id": stix_id,
      "collection_id": collection_id,
      "object_type": object_type,
      "name": name,
      "stix_payload": stix_payload,
      "source_ioc_id": None,
      "created_at": now,
      "modified": now,
    }

  @staticmethod
  def create_attack_pattern(
    name: str,
    external_id: str,
    collection_id: str,
  ) -> dict[str, Any]:
    now = utc_now()
    object_type = StixObjectType.ATTACK_PATTERN.value
    stix_id = generate_stix_id(object_type)

    stix_payload = {
      "type": object_type,
      "spec_version": STIX_SPEC_VERSION,
      "id": stix_id,
      "created": now.isoformat(),
      "modified": now.isoformat(),
      "name": name,
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": external_id,
        }
      ],
    }

    return {
      "stix_id": stix_id,
      "collection_id": collection_id,
      "object_type": object_type,
      "name": name,
      "stix_payload": stix_payload,
      "source_ioc_id": None,
      "created_at": now,
      "modified": now,
    }
