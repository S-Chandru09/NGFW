"""Seed MongoDB IOC database with sample IP, domain, and hash indicators."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from database import close_mongodb_connection, connect_to_mongodb, get_ioc_indicators_collection
from models.threat_intelligence import (
  HashReputationCreate,
  IOCDocument,
  MaliciousDomainCreate,
  ThreatCategory,
  IPReputationCreate,
)
from services.threat_intelligence_service import threat_intelligence_service

SAMPLE_IPS = [
  IPReputationCreate(
    ip_address="14.215.177.39",
    reputation_score=92,
    is_malicious=True,
    threat_categories=[ThreatCategory.BOTNET, ThreatCategory.C2],
    source="threat-feed",
    description="Known C2 server",
    country="CN",
    tags=["botnet", "c2"],
  ),
  IPReputationCreate(
    ip_address="95.108.213.141",
    reputation_score=88,
    is_malicious=True,
    threat_categories=[ThreatCategory.MALWARE],
    source="threat-feed",
    description="Malware distribution host",
    country="RU",
    tags=["malware"],
  ),
  IPReputationCreate(
    ip_address="8.8.8.8",
    reputation_score=5,
    is_malicious=False,
    threat_categories=[],
    source="whitelist",
    description="Trusted DNS resolver",
    country="US",
    tags=["trusted"],
  ),
]

SAMPLE_DOMAINS = [
  MaliciousDomainCreate(
    domain="malware-drop.example",
    reputation_score=95,
    is_malicious=True,
    threat_categories=[ThreatCategory.MALWARE],
    source="threat-feed",
    description="Malware payload delivery domain",
    tags=["malware", "dropper"],
  ),
  MaliciousDomainCreate(
    domain="phish-login.example",
    reputation_score=90,
    is_malicious=True,
    threat_categories=[ThreatCategory.PHISHING],
    source="threat-feed",
    description="Credential phishing portal",
    tags=["phishing"],
  ),
  MaliciousDomainCreate(
    domain="safe-cdn.example",
    reputation_score=10,
    is_malicious=False,
    threat_categories=[],
    source="internal",
    description="Verified CDN endpoint",
    tags=["trusted"],
  ),
]

SAMPLE_HASHES = [
  HashReputationCreate(
    hash_value="44d88612fea8a8f36de82e1278abb02f",
    reputation_score=98,
    is_malicious=True,
    threat_categories=[ThreatCategory.MALWARE],
    source="sandbox",
    description="EICAR test file MD5",
    tags=["eicar", "test"],
  ),
  HashReputationCreate(
    hash_value="275a021bbfb6489e54d471899f7db9a1",
    reputation_score=96,
    is_malicious=True,
    threat_categories=[ThreatCategory.RANSOMWARE],
    source="sandbox",
    description="Ransomware sample SHA1",
    tags=["ransomware"],
  ),
  HashReputationCreate(
    hash_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    reputation_score=0,
    is_malicious=False,
    threat_categories=[],
    source="internal",
    description="Empty file SHA256",
    tags=["benign"],
  ),
]


async def seed_ioc_database() -> None:
  await connect_to_mongodb()
  collection = get_ioc_indicators_collection()

  seeded = 0
  skipped = 0

  for ip_data in SAMPLE_IPS:
    ioc_create = ip_data.to_ioc_create()
    existing = await collection.find_one(
      {"value_hash": IOCDocument._build_value_hash(ioc_create.ioc_type.value, ioc_create.value)}
    )

    if existing:
      skipped += 1
      continue

    await threat_intelligence_service.create_ioc(ioc_create, created_by="seed-script")
    seeded += 1

  for domain_data in SAMPLE_DOMAINS:
    ioc_create = domain_data.to_ioc_create()
    existing = await collection.find_one(
      {"value_hash": IOCDocument._build_value_hash(ioc_create.ioc_type.value, ioc_create.value)}
    )

    if existing:
      skipped += 1
      continue

    await threat_intelligence_service.create_ioc(ioc_create, created_by="seed-script")
    seeded += 1

  for hash_data in SAMPLE_HASHES:
    ioc_create = hash_data.to_ioc_create()
    existing = await collection.find_one(
      {"value_hash": IOCDocument._build_value_hash(ioc_create.ioc_type.value, ioc_create.value)}
    )

    if existing:
      skipped += 1
      continue

    await threat_intelligence_service.create_ioc(ioc_create, created_by="seed-script")
    seeded += 1

  print(f"IOC database seed complete: {seeded} created, {skipped} skipped (already exist)")
  await close_mongodb_connection()


if __name__ == "__main__":
  asyncio.run(seed_ioc_database())
