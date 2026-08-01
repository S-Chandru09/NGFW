import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional
from uuid import uuid4

from bson import ObjectId
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator, model_validator


class IOCType(str, Enum):
  IP = "ip"
  HASH = "hash"
  DOMAIN = "domain"
  URL = "url"
  EMAIL = "email"


class HashType(str, Enum):
  MD5 = "md5"
  SHA1 = "sha1"
  SHA256 = "sha256"


class ThreatLevel(str, Enum):
  SAFE = "safe"
  LOW = "low"
  MEDIUM = "medium"
  HIGH = "high"
  CRITICAL = "critical"


class ThreatCategory(str, Enum):
  MALWARE = "malware"
  PHISHING = "phishing"
  C2 = "c2"
  BOTNET = "botnet"
  SPAM = "spam"
  EXPLOIT = "exploit"
  RANSOMWARE = "ransomware"
  DATA_EXFILTRATION = "data_exfiltration"
  BRUTE_FORCE = "brute_force"
  UNKNOWN = "unknown"


def validate_object_id(value: Any) -> str:
  if isinstance(value, ObjectId):
    return str(value)

  if isinstance(value, str) and ObjectId.is_valid(value):
    return value

  raise ValueError("Invalid ObjectId")


PyObjectId = Annotated[str, BeforeValidator(validate_object_id)]

DOMAIN_PATTERN = re.compile(
  r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
HASH_PATTERNS = {
  HashType.MD5: re.compile(r"^[a-fA-F0-9]{32}$"),
  HashType.SHA1: re.compile(r"^[a-fA-F0-9]{40}$"),
  HashType.SHA256: re.compile(r"^[a-fA-F0-9]{64}$"),
}


def detect_hash_type(value: str) -> Optional[HashType]:
  cleaned = value.strip().lower()

  if HASH_PATTERNS[HashType.MD5].match(cleaned):
    return HashType.MD5

  if HASH_PATTERNS[HashType.SHA1].match(cleaned):
    return HashType.SHA1

  if HASH_PATTERNS[HashType.SHA256].match(cleaned):
    return HashType.SHA256

  return None


def calculate_threat_level(reputation_score: int, is_malicious: bool) -> ThreatLevel:
  if not is_malicious and reputation_score < 20:
    return ThreatLevel.SAFE

  if reputation_score >= 90 or (is_malicious and reputation_score >= 80):
    return ThreatLevel.CRITICAL

  if reputation_score >= 70:
    return ThreatLevel.HIGH

  if reputation_score >= 40:
    return ThreatLevel.MEDIUM

  if reputation_score >= 20:
    return ThreatLevel.LOW

  return ThreatLevel.SAFE


class IOCBase(BaseModel):
  ioc_type: IOCType
  value: str = Field(..., min_length=1, max_length=500)
  hash_type: Optional[HashType] = None
  reputation_score: int = Field(default=50, ge=0, le=100)
  is_malicious: bool = False
  threat_categories: list[ThreatCategory] = Field(default_factory=list)
  source: str = Field(default="internal", max_length=100)
  description: Optional[str] = Field(default=None, max_length=1000)
  country: Optional[str] = Field(default=None, max_length=100)
  asn: Optional[str] = Field(default=None, max_length=50)
  isp: Optional[str] = Field(default=None, max_length=200)
  tags: list[str] = Field(default_factory=list)
  metadata: dict[str, Any] = Field(default_factory=dict)
  is_active: bool = True

  @field_validator("value")
  @classmethod
  def normalize_value(cls, value: str) -> str:
    return value.strip()

  @model_validator(mode="after")
  def validate_ioc_value(self):
    if self.ioc_type == IOCType.IP:
      try:
        ipaddress.ip_address(self.value)
      except ValueError as exc:
        raise ValueError("Invalid IP address format") from exc

    if self.ioc_type == IOCType.DOMAIN:
      if not DOMAIN_PATTERN.match(self.value.lower()):
        raise ValueError("Invalid domain format")

    if self.ioc_type == IOCType.HASH:
      detected_hash_type = detect_hash_type(self.value)
      if detected_hash_type is None:
        raise ValueError("Invalid hash format. Must be MD5, SHA1, or SHA256")

      if self.hash_type is None:
        self.hash_type = detected_hash_type
      elif self.hash_type != detected_hash_type:
        raise ValueError(f"Hash value does not match hash_type '{self.hash_type.value}'")

      self.value = self.value.lower()

    if self.ioc_type == IOCType.EMAIL:
      if "@" not in self.value:
        raise ValueError("Invalid email format")

    return self


class IOCCreate(IOCBase):
  pass


class IOCUpdate(BaseModel):
  reputation_score: Optional[int] = Field(default=None, ge=0, le=100)
  is_malicious: Optional[bool] = None
  threat_categories: Optional[list[ThreatCategory]] = None
  source: Optional[str] = Field(default=None, max_length=100)
  description: Optional[str] = Field(default=None, max_length=1000)
  country: Optional[str] = Field(default=None, max_length=100)
  asn: Optional[str] = Field(default=None, max_length=50)
  isp: Optional[str] = Field(default=None, max_length=200)
  tags: Optional[list[str]] = None
  metadata: Optional[dict[str, Any]] = None
  is_active: Optional[bool] = None


class IOCInDB(IOCBase):
  model_config = ConfigDict(populate_by_name=True)

  id: PyObjectId = Field(alias="_id")
  ioc_id: str
  threat_level: ThreatLevel
  value_hash: str
  first_seen_at: datetime
  last_seen_at: datetime
  hit_count: int = 0
  created_by: Optional[str] = None
  created_at: datetime
  updated_at: datetime


class IOCPublic(BaseModel):
  model_config = ConfigDict(populate_by_name=True)

  id: PyObjectId = Field(alias="_id")
  ioc_id: str
  ioc_type: IOCType
  value: str
  hash_type: Optional[HashType] = None
  reputation_score: int
  threat_level: ThreatLevel
  is_malicious: bool
  threat_categories: list[ThreatCategory]
  source: str
  description: Optional[str] = None
  country: Optional[str] = None
  asn: Optional[str] = None
  isp: Optional[str] = None
  tags: list[str]
  metadata: dict[str, Any]
  is_active: bool
  first_seen_at: datetime
  last_seen_at: datetime
  hit_count: int
  created_by: Optional[str] = None
  created_at: datetime
  updated_at: datetime


class IPReputationCreate(BaseModel):
  ip_address: str
  reputation_score: int = Field(default=50, ge=0, le=100)
  is_malicious: bool = False
  threat_categories: list[ThreatCategory] = Field(default_factory=list)
  source: str = Field(default="internal", max_length=100)
  description: Optional[str] = Field(default=None, max_length=1000)
  country: Optional[str] = None
  asn: Optional[str] = None
  isp: Optional[str] = None
  tags: list[str] = Field(default_factory=list)
  metadata: dict[str, Any] = Field(default_factory=dict)
  is_active: bool = True

  def to_ioc_create(self) -> IOCCreate:
    return IOCCreate(
      ioc_type=IOCType.IP,
      value=self.ip_address,
      reputation_score=self.reputation_score,
      is_malicious=self.is_malicious,
      threat_categories=self.threat_categories,
      source=self.source,
      description=self.description,
      country=self.country,
      asn=self.asn,
      isp=self.isp,
      tags=self.tags,
      metadata=self.metadata,
      is_active=self.is_active,
    )


class HashReputationCreate(BaseModel):
  hash_value: str
  hash_type: Optional[HashType] = None
  reputation_score: int = Field(default=50, ge=0, le=100)
  is_malicious: bool = False
  threat_categories: list[ThreatCategory] = Field(default_factory=list)
  source: str = Field(default="internal", max_length=100)
  description: Optional[str] = Field(default=None, max_length=1000)
  tags: list[str] = Field(default_factory=list)
  metadata: dict[str, Any] = Field(default_factory=dict)
  is_active: bool = True

  def to_ioc_create(self) -> IOCCreate:
    return IOCCreate(
      ioc_type=IOCType.HASH,
      value=self.hash_value,
      hash_type=self.hash_type,
      reputation_score=self.reputation_score,
      is_malicious=self.is_malicious,
      threat_categories=self.threat_categories,
      source=self.source,
      description=self.description,
      tags=self.tags,
      metadata=self.metadata,
      is_active=self.is_active,
    )


class MaliciousDomainCreate(BaseModel):
  domain: str
  reputation_score: int = Field(default=50, ge=0, le=100)
  is_malicious: bool = True
  threat_categories: list[ThreatCategory] = Field(default_factory=lambda: [ThreatCategory.PHISHING])
  source: str = Field(default="internal", max_length=100)
  description: Optional[str] = Field(default=None, max_length=1000)
  tags: list[str] = Field(default_factory=list)
  metadata: dict[str, Any] = Field(default_factory=dict)
  is_active: bool = True

  def to_ioc_create(self) -> IOCCreate:
    return IOCCreate(
      ioc_type=IOCType.DOMAIN,
      value=self.domain.lower(),
      reputation_score=self.reputation_score,
      is_malicious=self.is_malicious,
      threat_categories=self.threat_categories,
      source=self.source,
      description=self.description,
      tags=self.tags,
      metadata=self.metadata,
      is_active=self.is_active,
    )


class IOCDocument:
  @staticmethod
  def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

  @staticmethod
  def _build_value_hash(ioc_type: str, value: str) -> str:
    normalized = f"{ioc_type}:{value.lower().strip()}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

  @staticmethod
  def create_document(ioc_data: IOCCreate, created_by: Optional[str] = None) -> dict[str, Any]:
    now = IOCDocument._utc_now()
    threat_level = calculate_threat_level(ioc_data.reputation_score, ioc_data.is_malicious)

    return {
      "ioc_id": str(uuid4()),
      "ioc_type": ioc_data.ioc_type.value,
      "value": ioc_data.value.lower() if ioc_data.ioc_type in {IOCType.HASH, IOCType.DOMAIN} else ioc_data.value,
      "value_hash": IOCDocument._build_value_hash(ioc_data.ioc_type.value, ioc_data.value),
      "hash_type": ioc_data.hash_type.value if ioc_data.hash_type else None,
      "reputation_score": ioc_data.reputation_score,
      "threat_level": threat_level.value,
      "is_malicious": ioc_data.is_malicious,
      "threat_categories": [category.value for category in ioc_data.threat_categories],
      "source": ioc_data.source,
      "description": ioc_data.description,
      "country": ioc_data.country,
      "asn": ioc_data.asn,
      "isp": ioc_data.isp,
      "tags": ioc_data.tags,
      "metadata": ioc_data.metadata,
      "is_active": ioc_data.is_active,
      "first_seen_at": now,
      "last_seen_at": now,
      "hit_count": 0,
      "created_by": created_by,
      "created_at": now,
      "updated_at": now,
    }

  @staticmethod
  def update_document(existing_ioc: dict[str, Any], update_data: IOCUpdate) -> dict[str, Any]:
    update_fields = update_data.model_dump(exclude_unset=True)

    if update_data.threat_categories is not None:
      update_fields["threat_categories"] = [category.value for category in update_data.threat_categories]

    merged = {**existing_ioc, **update_fields}
    reputation_score = merged.get("reputation_score", 0)
    is_malicious = merged.get("is_malicious", False)
    update_fields["threat_level"] = calculate_threat_level(reputation_score, is_malicious).value
    update_fields["updated_at"] = IOCDocument._utc_now()

    return {**existing_ioc, **update_fields}

  @staticmethod
  def from_mongo(document: Optional[dict[str, Any]]) -> Optional[IOCInDB]:
    if document is None:
      return None

    document_copy = dict(document)
    document_copy["_id"] = str(document_copy["_id"])
    return IOCInDB(**document_copy)

  @staticmethod
  def to_public(ioc: IOCInDB) -> IOCPublic:
    return IOCPublic(
      _id=ioc.id,
      ioc_id=ioc.ioc_id,
      ioc_type=ioc.ioc_type,
      value=ioc.value,
      hash_type=ioc.hash_type,
      reputation_score=ioc.reputation_score,
      threat_level=ioc.threat_level,
      is_malicious=ioc.is_malicious,
      threat_categories=ioc.threat_categories,
      source=ioc.source,
      description=ioc.description,
      country=ioc.country,
      asn=ioc.asn,
      isp=ioc.isp,
      tags=ioc.tags,
      metadata=ioc.metadata,
      is_active=ioc.is_active,
      first_seen_at=ioc.first_seen_at,
      last_seen_at=ioc.last_seen_at,
      hit_count=ioc.hit_count,
      created_by=ioc.created_by,
      created_at=ioc.created_at,
      updated_at=ioc.updated_at,
    )

  @staticmethod
  def to_public_from_mongo(document: Optional[dict[str, Any]]) -> Optional[IOCPublic]:
    ioc = IOCDocument.from_mongo(document)
    if ioc is None:
      return None
    return IOCDocument.to_public(ioc)
