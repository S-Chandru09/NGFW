from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
  model_config = SettingsConfigDict(
    env_file=".env",
    env_file_encoding="utf-8",
    case_sensitive=False,
    extra="ignore",
  )

  # Application
  app_name: str = Field(default="AI-NGFW Zero Trust Firewall", alias="APP_NAME")
  app_version: str = Field(default="1.0.0", alias="APP_VERSION")
  app_description: str = Field(
    default="AI-Powered Next Generation Firewall with Zero Trust Architecture",
    alias="APP_DESCRIPTION",
  )
  environment: str = Field(default="development", alias="ENVIRONMENT")
  debug: bool = Field(default=True, alias="DEBUG")
  api_v1_prefix: str = Field(default="/api/v1", alias="API_V1_PREFIX")

  # Server
  host: str = Field(default="0.0.0.0", alias="HOST")
  port: int = Field(default=8000, alias="PORT")
  reload: bool = Field(default=True, alias="RELOAD")

  # Security
  secret_key: str = Field(
    default="change-this-secret-key-in-production-use-openssl-rand-hex-32",
    alias="SECRET_KEY",
  )
  algorithm: str = Field(default="HS256", alias="ALGORITHM")
  access_token_expire_minutes: int = Field(default=30, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
  refresh_token_expire_days: int = Field(default=7, alias="REFRESH_TOKEN_EXPIRE_DAYS")

  # CORS
  cors_origins: List[str] = Field(
    default=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    alias="CORS_ORIGINS",
  )
  cors_allow_credentials: bool = Field(default=True, alias="CORS_ALLOW_CREDENTIALS")
  cors_allow_methods: List[str] = Field(default=["*"], alias="CORS_ALLOW_METHODS")
  cors_allow_headers: List[str] = Field(default=["*"], alias="CORS_ALLOW_HEADERS")

  # MongoDB
  mongodb_url: str = Field(
    default="mongodb://localhost:27017",
    alias="MONGODB_URL",
  )
  mongodb_database: str = Field(default="ai_ngfw", alias="MONGODB_DATABASE")
  mongodb_min_pool_size: int = Field(default=1, alias="MONGODB_MIN_POOL_SIZE")
  mongodb_max_pool_size: int = Field(default=10, alias="MONGODB_MAX_POOL_SIZE")

  # Zero Trust
  zero_trust_enabled: bool = Field(default=True, alias="ZERO_TRUST_ENABLED")
  default_device_trust_score: float = Field(default=50.0, alias="DEFAULT_DEVICE_TRUST_SCORE")
  min_trust_score_for_access: float = Field(default=60.0, alias="MIN_TRUST_SCORE_FOR_ACCESS")

  # ML Models
  ml_models_path: str = Field(default="../ml/models", alias="ML_MODELS_PATH")
  sklearn_model_filename: str = Field(default="sklearn/threat_classifier.pkl", alias="SKLEARN_MODEL_FILENAME")
  tensorflow_model_path: str = Field(default="tensorflow/threat_classifier", alias="TENSORFLOW_MODEL_PATH")
  ml_inference_threshold: float = Field(default=0.75, alias="ML_INFERENCE_THRESHOLD")

  # Network Capture
  network_capture_enabled: bool = Field(default=True, alias="NETWORK_CAPTURE_ENABLED")
  capture_interface: str = Field(default="eth0", alias="CAPTURE_INTERFACE")
  capture_bpf_filter: str = Field(default="ip or ip6", alias="CAPTURE_BPF_FILTER")
  pcap_storage_path: str = Field(default="../network/pcap/incoming", alias="PCAP_STORAGE_PATH")
  pcap_max_file_size_mb: int = Field(default=100, alias="PCAP_MAX_FILE_SIZE_MB")

  # Internal service authentication
  internal_api_key: Optional[str] = Field(default=None, alias="INTERNAL_API_KEY")

  # AI Engine
  ai_engine_enabled: bool = Field(default=True, alias="AI_ENGINE_ENABLED")
  ai_engine_url: str = Field(default="http://localhost:8001", alias="AI_ENGINE_URL")
  ai_engine_analyze_endpoint: str = Field(default="/api/v1/analyze/pcap", alias="AI_ENGINE_ANALYZE_ENDPOINT")
  ai_engine_live_endpoint: str = Field(default="/api/v1/analyze/live", alias="AI_ENGINE_LIVE_ENDPOINT")
  ai_engine_timeout_seconds: int = Field(default=600, alias="AI_ENGINE_TIMEOUT_SECONDS")

  # Logging
  log_level: str = Field(default="INFO", alias="LOG_LEVEL")
  log_format: str = Field(default="json", alias="LOG_FORMAT")

  # Rate Limiting
  rate_limit_enabled: bool = Field(default=True, alias="RATE_LIMIT_ENABLED")
  rate_limit_requests: int = Field(default=100, alias="RATE_LIMIT_REQUESTS")
  rate_limit_window_seconds: int = Field(default=60, alias="RATE_LIMIT_WINDOW_SECONDS")

  @field_validator("cors_origins", "cors_allow_methods", "cors_allow_headers", mode="before")
  @classmethod
  def parse_comma_separated_list(cls, value):
    if isinstance(value, str):
      return [item.strip() for item in value.split(",") if item.strip()]
    return value

  @property
  def is_development(self) -> bool:
    return self.environment.lower() == "development"

  @property
  def is_production(self) -> bool:
    return self.environment.lower() == "production"

  @property
  def mongodb_connection_string(self) -> str:
    return self.mongodb_url


@lru_cache
def get_settings() -> Settings:
  return Settings()


settings = get_settings()
