"""
Attack classifier for the AI-NGFW threat detection pipeline.

Maps ML predictions and raw labels to supported attack categories:
Normal, DDoS, Botnet, Port Scan, Brute Force, SQL Injection, XSS, and Malware.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Union

from ml.predict import AttackPredictionResult

logger = logging.getLogger("ai-engine.attack_classifier")


class AttackCategory(str, Enum):
  NORMAL = "Normal"
  DDOS = "DDoS"
  BOTNET = "Botnet"
  PORT_SCAN = "Port Scan"
  BRUTE_FORCE = "Brute Force"
  SQL_INJECTION = "SQL Injection"
  XSS = "XSS"
  MALWARE = "Malware"


SUPPORTED_ATTACKS = [category.value for category in AttackCategory]

ATTACK_METADATA: dict[str, dict[str, str]] = {
  AttackCategory.NORMAL.value: {
    "severity": "low",
    "description": "Legitimate network traffic with no detected attack patterns.",
    "recommended_action": "allow",
  },
  AttackCategory.DDOS.value: {
    "severity": "critical",
    "description": "Distributed denial-of-service attack attempting to overwhelm network resources.",
    "recommended_action": "block",
  },
  AttackCategory.BOTNET.value: {
    "severity": "critical",
    "description": "Botnet command-and-control or infected host communication detected.",
    "recommended_action": "quarantine",
  },
  AttackCategory.PORT_SCAN.value: {
    "severity": "medium",
    "description": "Reconnaissance activity scanning multiple ports or hosts.",
    "recommended_action": "monitor",
  },
  AttackCategory.BRUTE_FORCE.value: {
    "severity": "high",
    "description": "Repeated authentication attempts indicating credential brute-force activity.",
    "recommended_action": "block",
  },
  AttackCategory.SQL_INJECTION.value: {
    "severity": "critical",
    "description": "Web attack attempting SQL injection against application endpoints.",
    "recommended_action": "block",
  },
  AttackCategory.XSS.value: {
    "severity": "high",
    "description": "Cross-site scripting attack targeting web application users.",
    "recommended_action": "block",
  },
  AttackCategory.MALWARE.value: {
    "severity": "critical",
    "description": "Malicious traffic consistent with malware delivery or exploitation.",
    "recommended_action": "quarantine",
  },
}

LABEL_ALIAS_MAP: dict[str, AttackCategory] = {
  "BENIGN": AttackCategory.NORMAL,
  "BENIGN_TRAFFIC": AttackCategory.NORMAL,
  "NORMAL": AttackCategory.NORMAL,
  "ANOMALY": AttackCategory.MALWARE,
  "UNKNOWN": AttackCategory.MALWARE,
  "DDOS": AttackCategory.DDOS,
  "DDOS_ATTACK": AttackCategory.DDOS,
  "DOS": AttackCategory.DDOS,
  "DOS_ATTACK": AttackCategory.DDOS,
  "DDOS_HULK": AttackCategory.DDOS,
  "DDOS_GOLDENEYE": AttackCategory.DDOS,
  "DDOS_SLOWLORIS": AttackCategory.DDOS,
  "DDOS_SLOWHTTPTEST": AttackCategory.DDOS,
  "DOS_HULK": AttackCategory.DDOS,
  "DOS_GOLDENEYE": AttackCategory.DDOS,
  "DOS_SLOWLORIS": AttackCategory.DDOS,
  "DOS_SLOWHTTPTEST": AttackCategory.DDOS,
  "BOT": AttackCategory.BOTNET,
  "BOTNET": AttackCategory.BOTNET,
  "BOT_ATTACK": AttackCategory.BOTNET,
  "PORTSCAN": AttackCategory.PORT_SCAN,
  "PORT_SCAN": AttackCategory.PORT_SCAN,
  "PORT-SCAN": AttackCategory.PORT_SCAN,
  "RECONNAISSANCE": AttackCategory.PORT_SCAN,
  "FTP_PATATOR": AttackCategory.BRUTE_FORCE,
  "SSH_PATATOR": AttackCategory.BRUTE_FORCE,
  "BRUTE_FORCE": AttackCategory.BRUTE_FORCE,
  "BRUTEFORCE": AttackCategory.BRUTE_FORCE,
  "WEB_ATTACK_BRUTE_FORCE": AttackCategory.BRUTE_FORCE,
  "WEB_ATTACK_SQL_INJECTION": AttackCategory.SQL_INJECTION,
  "SQL_INJECTION": AttackCategory.SQL_INJECTION,
  "SQLI": AttackCategory.SQL_INJECTION,
  "WEB_ATTACK_XSS": AttackCategory.XSS,
  "XSS": AttackCategory.XSS,
  "CROSS_SITE_SCRIPTING": AttackCategory.XSS,
  "MALWARE": AttackCategory.MALWARE,
  "INFILTRATION": AttackCategory.MALWARE,
  "HEARTBLEED": AttackCategory.MALWARE,
  "EXPLOIT": AttackCategory.MALWARE,
}


@dataclass
class AttackClassificationResult:
  category: str
  raw_label: str
  confidence: float
  is_attack: bool
  severity: str
  threat_level: str
  description: str
  recommended_action: str
  supported_category: bool = True
  classification_method: str = "label_mapping"
  metadata: dict[str, Any] = field(default_factory=dict)
  classified_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

  def to_dict(self) -> dict[str, Any]:
    return asdict(self)


@dataclass
class AttackClassifierConfig:
  default_unknown_category: AttackCategory = AttackCategory.MALWARE
  anomaly_category: AttackCategory = AttackCategory.MALWARE
  enable_feature_heuristics: bool = True
  minimum_attack_confidence: float = 0.5


class AttackClassifier:
  """Classify predictions into supported attack categories."""

  def __init__(self, config: Optional[AttackClassifierConfig] = None) -> None:
    self.config = config or AttackClassifierConfig()

  @staticmethod
  def get_supported_attacks() -> list[str]:
    return SUPPORTED_ATTACKS.copy()

  @staticmethod
  def normalize_label(raw_label: str) -> str:
    normalized = raw_label.strip().upper()
    normalized = normalized.replace("-", "_")
    normalized = normalized.replace(" ", "_")
    normalized = re.sub(r"[^A-Z0-9_]", "", normalized)
    normalized = re.sub(r"_+", "_", normalized)
    return normalized.strip("_")

  def _map_label_to_category(self, raw_label: str) -> tuple[AttackCategory, bool]:
    normalized_label = self.normalize_label(raw_label)

    if normalized_label in LABEL_ALIAS_MAP:
      return LABEL_ALIAS_MAP[normalized_label], True

    for alias, category in LABEL_ALIAS_MAP.items():
      if alias in normalized_label or normalized_label in alias:
        return category, True

    if "DDOS" in normalized_label or normalized_label.startswith("DOS"):
      return AttackCategory.DDOS, True

    if "BOT" in normalized_label:
      return AttackCategory.BOTNET, True

    if "PORT" in normalized_label and "SCAN" in normalized_label:
      return AttackCategory.PORT_SCAN, True

    if "BRUTE" in normalized_label or "PATATOR" in normalized_label:
      return AttackCategory.BRUTE_FORCE, True

    if "SQL" in normalized_label and "INJECTION" in normalized_label:
      return AttackCategory.SQL_INJECTION, True

    if "XSS" in normalized_label or "SCRIPT" in normalized_label:
      return AttackCategory.XSS, True

    if normalized_label in {"BENIGN", "NORMAL"}:
      return AttackCategory.NORMAL, True

    return self.config.default_unknown_category, False

  def _severity_to_threat_level(self, severity: str, confidence: float) -> str:
    if severity == "low":
      return "low"

    if confidence >= 0.85:
      return "high"

    if confidence >= 0.6:
      return "medium"

    return "low"

  def _build_result(
    self,
    category: AttackCategory,
    raw_label: str,
    confidence: float,
    classification_method: str,
    supported_category: bool = True,
    metadata: Optional[dict[str, Any]] = None,
  ) -> AttackClassificationResult:
    attack_metadata = ATTACK_METADATA[category.value]
    is_attack = category != AttackCategory.NORMAL
    severity = attack_metadata["severity"]
    threat_level = self._severity_to_threat_level(severity, confidence)

    return AttackClassificationResult(
      category=category.value,
      raw_label=raw_label,
      confidence=float(confidence),
      is_attack=is_attack,
      severity=severity,
      threat_level=threat_level,
      description=attack_metadata["description"],
      recommended_action=attack_metadata["recommended_action"],
      supported_category=supported_category,
      classification_method=classification_method,
      metadata=metadata or {},
    )

  def _classify_from_features(self, features: dict[str, Any]) -> Optional[AttackClassificationResult]:
    if not self.config.enable_feature_heuristics:
      return None

    flow_packets_s = float(features.get("flow_packets_s", 0.0))
    flow_bytes_s = float(features.get("flow_bytes_s", 0.0))
    total_fwd_packets = float(features.get("total_fwd_packets", 0.0))
    total_backward_packets = float(features.get("total_backward_packets", 0.0))
    destination_port = int(features.get("destination_port", 0) or 0)
    syn_flag_count = float(features.get("syn_flag_count", 0.0))
    rst_flag_count = float(features.get("rst_flag_count", 0.0))
    down_up_ratio = float(features.get("down_up_ratio", 0.0))

    if flow_packets_s > 1000 or flow_bytes_s > 1_000_000:
      return self._build_result(
        category=AttackCategory.DDOS,
        raw_label="HEURISTIC_DDOS",
        confidence=min(0.95, 0.6 + (flow_packets_s / 5000)),
        classification_method="feature_heuristics",
        metadata={"reason": "high_packet_or_byte_rate"},
      )

    if syn_flag_count >= 5 and total_backward_packets <= 1 and total_fwd_packets >= 5:
      return self._build_result(
        category=AttackCategory.PORT_SCAN,
        raw_label="HEURISTIC_PORT_SCAN",
        confidence=0.72,
        classification_method="feature_heuristics",
        metadata={"reason": "high_syn_count_with_low_response"},
      )

    if destination_port in {21, 22, 23, 3389, 3306, 5432} and total_fwd_packets >= 10 and down_up_ratio < 0.2:
      return self._build_result(
        category=AttackCategory.BRUTE_FORCE,
        raw_label="HEURISTIC_BRUTE_FORCE",
        confidence=0.7,
        classification_method="feature_heuristics",
        metadata={"reason": "repeated_auth_port_access", "destination_port": destination_port},
      )

    if destination_port in {80, 443, 8080, 8443} and flow_packets_s > 50 and rst_flag_count == 0:
      if total_fwd_packets > total_backward_packets * 3:
        return self._build_result(
          category=AttackCategory.SQL_INJECTION,
          raw_label="HEURISTIC_SQL_INJECTION",
          confidence=0.65,
          classification_method="feature_heuristics",
          metadata={"reason": "asymmetric_web_traffic"},
        )

    if syn_flag_count > 0 and rst_flag_count > 3 and total_fwd_packets > 20:
      return self._build_result(
        category=AttackCategory.BOTNET,
        raw_label="HEURISTIC_BOTNET",
        confidence=0.68,
        classification_method="feature_heuristics",
        metadata={"reason": "suspicious_connection_pattern"},
      )

    return None

  def classify_label(
    self,
    raw_label: str,
    confidence: float,
    features: Optional[dict[str, Any]] = None,
  ) -> AttackClassificationResult:
    """Classify a raw ML label into a supported attack category."""
    category, supported = self._map_label_to_category(raw_label)

    if category == AttackCategory.NORMAL:
      return self._build_result(
        category=category,
        raw_label=raw_label,
        confidence=confidence,
        classification_method="label_mapping",
        supported_category=supported,
      )

    if self.normalize_label(raw_label) == "ANOMALY" and features:
      heuristic_result = self._classify_from_features(features)
      if heuristic_result is not None:
        heuristic_result.confidence = max(heuristic_result.confidence, confidence)
        heuristic_result.raw_label = raw_label
        return heuristic_result

      category = self.config.anomaly_category
      supported = False

    return self._build_result(
      category=category,
      raw_label=raw_label,
      confidence=confidence,
      classification_method="label_mapping",
      supported_category=supported,
    )

  def classify_prediction(
    self,
    prediction: AttackPredictionResult,
    features: Optional[dict[str, Any]] = None,
  ) -> AttackClassificationResult:
    """Classify an AttackPredictionResult from predict.py."""
    return self.classify_label(
      raw_label=prediction.attack_label,
      confidence=prediction.confidence,
      features=features,
    )

  def classify(
    self,
    raw_label: Optional[str] = None,
    confidence: float = 0.0,
    prediction: Optional[AttackPredictionResult] = None,
    features: Optional[dict[str, Any]] = None,
  ) -> AttackClassificationResult:
    """Classify using a raw label or an existing prediction result."""
    if prediction is not None:
      return self.classify_prediction(prediction=prediction, features=features)

    if raw_label is None:
      raise ValueError("Either raw_label or prediction must be provided")

    return self.classify_label(raw_label=raw_label, confidence=confidence, features=features)

  def is_normal(self, category: str) -> bool:
    return category == AttackCategory.NORMAL.value

  def is_supported_category(self, category: str) -> bool:
    return category in SUPPORTED_ATTACKS

  def get_category_metadata(self, category: str) -> dict[str, str]:
    if category not in ATTACK_METADATA:
      raise ValueError(f"Unsupported attack category: {category}")
    return ATTACK_METADATA[category].copy()


def classify_attack(
  raw_label: Optional[str] = None,
  confidence: float = 0.0,
  prediction: Optional[AttackPredictionResult] = None,
  features: Optional[dict[str, Any]] = None,
) -> AttackClassificationResult:
  """Convenience helper to classify an attack."""
  classifier = AttackClassifier()
  return classifier.classify(
    raw_label=raw_label,
    confidence=confidence,
    prediction=prediction,
    features=features,
  )


def get_supported_attack_types() -> list[str]:
  """Return all supported attack categories."""
  return AttackClassifier.get_supported_attacks()


if __name__ == "__main__":
  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
  )

  samples = [
    ("BENIGN", 0.98),
    ("DDoS", 0.91),
    ("PortScan", 0.87),
    ("Web Attack – Sql Injection", 0.89),
    ("Web Attack – XSS", 0.84),
    ("Bot", 0.93),
    ("FTP-Patator", 0.88),
    ("ANOMALY", 0.76),
  ]

  classifier = AttackClassifier()

  for label, confidence in samples:
    result = classifier.classify_label(label, confidence)
    print(json.dumps(result.to_dict(), indent=2))
