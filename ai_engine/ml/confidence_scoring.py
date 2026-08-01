"""
Confidence scoring module for the AI-NGFW threat detection pipeline.

Combines ML predictions and attack classification to return prediction,
probability, and threat level with model agreement metrics.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Union

from ml.attack_classifier import (
  ATTACK_METADATA,
  AttackCategory,
  AttackClassificationResult,
  AttackClassifier,
  SUPPORTED_ATTACKS,
)
from ml.predict import AttackPredictionResult, AttackPredictor, load_predictor

logger = logging.getLogger("ai-engine.confidence_scoring")


class ThreatLevel(str, Enum):
  LOW = "low"
  MEDIUM = "medium"
  HIGH = "high"
  CRITICAL = "critical"


CRITICAL_ATTACK_CATEGORIES = {
  AttackCategory.DDOS.value,
  AttackCategory.BOTNET.value,
  AttackCategory.SQL_INJECTION.value,
  AttackCategory.MALWARE.value,
}

HIGH_ATTACK_CATEGORIES = {
  AttackCategory.BRUTE_FORCE.value,
  AttackCategory.XSS.value,
}

DEFAULT_HIGH_THRESHOLD = 0.85
DEFAULT_MEDIUM_THRESHOLD = 0.60
DEFAULT_LOW_THRESHOLD = 0.40


@dataclass
class ConfidenceScoringConfig:
  high_threshold: float = DEFAULT_HIGH_THRESHOLD
  medium_threshold: float = DEFAULT_MEDIUM_THRESHOLD
  low_threshold: float = DEFAULT_LOW_THRESHOLD
  use_model_agreement_boost: bool = True
  agreement_boost_weight: float = 0.1


@dataclass
class ConfidenceScoreResult:
  prediction: str
  probability: float
  threat_level: str
  is_attack: bool
  raw_label: str
  model_agreement: float
  probabilities: dict[str, float] = field(default_factory=dict)
  model_probabilities: dict[str, float] = field(default_factory=dict)
  severity: str = "low"
  recommended_action: str = "allow"
  confidence_band: str = "low"
  scored_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

  def to_dict(self) -> dict[str, Any]:
    return asdict(self)


class ConfidenceScorer:
  """Calculate prediction confidence, probability, and threat level."""

  def __init__(
    self,
    config: Optional[ConfidenceScoringConfig] = None,
    classifier: Optional[AttackClassifier] = None,
    predictor: Optional[AttackPredictor] = None,
  ) -> None:
    self.config = config or ConfidenceScoringConfig()
    self.classifier = classifier or AttackClassifier()
    self.predictor = predictor

  def _clamp_probability(self, value: float) -> float:
    return float(max(0.0, min(1.0, value)))

  def _confidence_band(self, probability: float) -> str:
    if probability >= self.config.high_threshold:
      return "high"

    if probability >= self.config.medium_threshold:
      return "medium"

    if probability >= self.config.low_threshold:
      return "low"

    return "very_low"

  def _calculate_model_agreement(self, prediction: AttackPredictionResult) -> float:
    if not prediction.model_predictions:
      return 0.0

    agreeing_models = [
      model_prediction
      for model_prediction in prediction.model_predictions
      if model_prediction.attack_label == prediction.attack_label
    ]

    if not agreeing_models:
      return 0.0

    agreement_ratio = len(agreeing_models) / len(prediction.model_predictions)
    weighted_confidence = sum(
      model_prediction.confidence for model_prediction in agreeing_models
    ) / len(agreeing_models)

    return self._clamp_probability((agreement_ratio * 0.5) + (weighted_confidence * 0.5))

  def _build_model_probability_map(
    self,
    prediction: AttackPredictionResult,
  ) -> dict[str, float]:
    model_probabilities: dict[str, float] = {}

    for model_prediction in prediction.model_predictions:
      model_probabilities[model_prediction.model_name] = self._clamp_probability(
        model_prediction.confidence
      )

    return model_probabilities

  def _build_category_probabilities(
    self,
    prediction: AttackPredictionResult,
    classification: AttackClassificationResult,
  ) -> dict[str, float]:
    category_probabilities = {category: 0.0 for category in SUPPORTED_ATTACKS}

    for model_prediction in prediction.model_predictions:
      mapped = self.classifier.classify_label(
        raw_label=model_prediction.attack_label,
        confidence=model_prediction.confidence,
      )
      category_probabilities[mapped.category] += mapped.confidence

    total_probability = sum(category_probabilities.values())
    if total_probability > 0:
      category_probabilities = {
        category: self._clamp_probability(score / total_probability)
        for category, score in category_probabilities.items()
      }
    else:
      category_probabilities[classification.category] = classification.confidence

    return category_probabilities

  def _apply_agreement_boost(
    self,
    probability: float,
    model_agreement: float,
  ) -> float:
    if not self.config.use_model_agreement_boost:
      return probability

    boost = model_agreement * self.config.agreement_boost_weight
    return self._clamp_probability(probability + boost)

  def _resolve_threat_level(
    self,
    prediction: str,
    probability: float,
    severity: str,
  ) -> str:
    if prediction == AttackCategory.NORMAL.value:
      return ThreatLevel.LOW.value

    if probability < self.config.low_threshold:
      return ThreatLevel.LOW.value

    if prediction in CRITICAL_ATTACK_CATEGORIES:
      if probability >= self.config.medium_threshold:
        return ThreatLevel.CRITICAL.value
      return ThreatLevel.MEDIUM.value

    if prediction in HIGH_ATTACK_CATEGORIES:
      if probability >= self.config.high_threshold:
        return ThreatLevel.HIGH.value
      if probability >= self.config.medium_threshold:
        return ThreatLevel.MEDIUM.value
      return ThreatLevel.LOW.value

    if severity == "critical" and probability >= self.config.high_threshold:
      return ThreatLevel.CRITICAL.value

    if probability >= self.config.high_threshold:
      return ThreatLevel.HIGH.value

    if probability >= self.config.medium_threshold:
      return ThreatLevel.MEDIUM.value

    return ThreatLevel.LOW.value

  def score_from_prediction(
    self,
    prediction: AttackPredictionResult,
    features: Optional[dict[str, Any]] = None,
  ) -> ConfidenceScoreResult:
    """Score confidence from an ML prediction result."""
    classification = self.classifier.classify_prediction(
      prediction=prediction,
      features=features,
    )
    return self.score_from_classification(
      prediction=prediction,
      classification=classification,
    )

  def score_from_classification(
    self,
    prediction: AttackPredictionResult,
    classification: AttackClassificationResult,
  ) -> ConfidenceScoreResult:
    """Score confidence from prediction and classification results."""
    model_agreement = self._calculate_model_agreement(prediction)
    probability = self._apply_agreement_boost(classification.confidence, model_agreement)
    threat_level = self._resolve_threat_level(
      prediction=classification.category,
      probability=probability,
      severity=classification.severity,
    )

    category_metadata = ATTACK_METADATA.get(classification.category, ATTACK_METADATA[AttackCategory.NORMAL.value])

    return ConfidenceScoreResult(
      prediction=classification.category,
      probability=probability,
      threat_level=threat_level,
      is_attack=classification.is_attack,
      raw_label=classification.raw_label,
      model_agreement=model_agreement,
      probabilities=self._build_category_probabilities(prediction, classification),
      model_probabilities=self._build_model_probability_map(prediction),
      severity=classification.severity,
      recommended_action=category_metadata["recommended_action"],
      confidence_band=self._confidence_band(probability),
    )

  def score(
    self,
    features: Union[dict[str, Any], Any],
    prediction: Optional[AttackPredictionResult] = None,
  ) -> ConfidenceScoreResult:
    """
    Score features and return prediction, probability, and threat level.

    If a prediction is not provided, runs the ML predictor first.
    """
    if prediction is None:
      if self.predictor is None:
        self.predictor = load_predictor()
      prediction = self.predictor.predict(features)

    feature_dict = features if isinstance(features, dict) else None
    return self.score_from_prediction(prediction=prediction, features=feature_dict)

  def score_label(
    self,
    raw_label: str,
    confidence: float,
    features: Optional[dict[str, Any]] = None,
  ) -> ConfidenceScoreResult:
    """Score a raw label and confidence without full ML ensemble details."""
    classification = self.classifier.classify_label(
      raw_label=raw_label,
      confidence=confidence,
      features=features,
    )

    synthetic_prediction = AttackPredictionResult(
      attack_label=raw_label,
      confidence=confidence,
      is_attack=classification.is_attack,
      threat_level=classification.threat_level,
      model_predictions=[],
      ensemble_method="label_only",
    )

    probability = self._clamp_probability(confidence)
    threat_level = self._resolve_threat_level(
      prediction=classification.category,
      probability=probability,
      severity=classification.severity,
    )

    category_metadata = ATTACK_METADATA.get(
      classification.category,
      ATTACK_METADATA[AttackCategory.NORMAL.value],
    )

    probabilities = {category: 0.0 for category in SUPPORTED_ATTACKS}
    probabilities[classification.category] = probability

    return ConfidenceScoreResult(
      prediction=classification.category,
      probability=probability,
      threat_level=threat_level,
      is_attack=classification.is_attack,
      raw_label=raw_label,
      model_agreement=0.0,
      probabilities=probabilities,
      model_probabilities={},
      severity=classification.severity,
      recommended_action=category_metadata["recommended_action"],
      confidence_band=self._confidence_band(probability),
    )


def score_confidence(
  features: Optional[Union[dict[str, Any], Any]] = None,
  prediction: Optional[AttackPredictionResult] = None,
  raw_label: Optional[str] = None,
  confidence: float = 0.0,
) -> ConfidenceScoreResult:
  """Convenience helper to return prediction, probability, and threat level."""
  scorer = ConfidenceScorer()

  if prediction is not None:
    feature_dict = features if isinstance(features, dict) else None
    return scorer.score_from_prediction(prediction=prediction, features=feature_dict)

  if raw_label is not None:
    return scorer.score_label(
      raw_label=raw_label,
      confidence=confidence,
      features=features if isinstance(features, dict) else None,
    )

  if features is None:
    raise ValueError("Either features, prediction, or raw_label must be provided")

  return scorer.score(features=features)


if __name__ == "__main__":
  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
  )

  samples = [
    ("BENIGN", 0.97),
    ("DDoS", 0.92),
    ("PortScan", 0.78),
    ("Web Attack – Sql Injection", 0.89),
    ("ANOMALY", 0.66),
  ]

  scorer = ConfidenceScorer()

  for label, confidence in samples:
    result = scorer.score_label(raw_label=label, confidence=confidence)
    print(json.dumps(result.to_dict(), indent=2))
