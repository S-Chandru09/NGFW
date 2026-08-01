"""
Unified attack prediction module for the AI-NGFW ML pipeline.

Loads all trained models (Random Forest, Isolation Forest, DBSCAN, CNN),
runs ensemble inference, and returns attack labels with confidence scores.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

import joblib
import numpy as np
from sklearn.neighbors import NearestNeighbors

from ml.features.feature_extraction import (
  DEFAULT_FEATURES_OUTPUT_PATH,
  ISOLATION_FOREST_FEATURE_KEYWORDS,
  FeatureExtractionConfig,
  FeatureExtractor,
)
from ml.preprocessing.preprocessing import DEFAULT_PROCESSED_DATA_PATH
from ml.training.train_cnn import CNNPredictionHelper

logger = logging.getLogger("ai-engine.predict")

DEFAULT_SKLEARN_MODEL_PATH = Path(__file__).resolve().parent / "models" / "sklearn"
DEFAULT_TENSORFLOW_MODEL_PATH = Path(__file__).resolve().parent / "models" / "tensorflow"
DEFAULT_BENIGN_LABEL = "BENIGN"
DEFAULT_ANOMALY_LABEL = "ANOMALY"

MODEL_WEIGHTS = {
  "random_forest": 0.35,
  "cnn": 0.35,
  "isolation_forest": 0.15,
  "dbscan": 0.15,
}


@dataclass
class ModelPrediction:
  model_name: str
  attack_label: str
  confidence: float
  is_attack: bool
  details: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPredictionResult:
  attack_label: str
  confidence: float
  is_attack: bool
  threat_level: str
  model_predictions: list[ModelPrediction]
  ensemble_method: str

  def to_dict(self) -> dict[str, Any]:
    payload = asdict(self)
    payload["model_predictions"] = [asdict(prediction) for prediction in self.model_predictions]
    return payload


@dataclass
class PredictorConfig:
  sklearn_model_path: Path = DEFAULT_SKLEARN_MODEL_PATH
  tensorflow_model_path: Path = DEFAULT_TENSORFLOW_MODEL_PATH
  processed_data_path: Path = DEFAULT_PROCESSED_DATA_PATH
  features_path: Path = DEFAULT_FEATURES_OUTPUT_PATH
  benign_label: str = DEFAULT_BENIGN_LABEL
  anomaly_label: str = DEFAULT_ANOMALY_LABEL
  model_weights: dict[str, float] = field(default_factory=lambda: MODEL_WEIGHTS.copy())
  dbscan_metric: str = "euclidean"
  require_scaled_input: bool = False


class AttackPredictor:
  """Load all trained models and predict network attacks with confidence scores."""

  def __init__(self, config: Optional[PredictorConfig] = None) -> None:
    self.config = config or PredictorConfig()
    self.random_forest_model = None
    self.isolation_forest_model = None
    self.dbscan_model = None
    self.dbscan_pca_model = None
    self.cnn_predictor: Optional[CNNPredictionHelper] = None

    self.scaler = None
    self.label_encoder = None
    self.feature_columns: list[str] = []
    self.label_classes: list[str] = []
    self.isolation_feature_indices: list[int] = []

    self.dbscan_reference_features: Optional[np.ndarray] = None
    self.dbscan_reference_labels: Optional[np.ndarray] = None
    self.dbscan_nearest_neighbors: Optional[NearestNeighbors] = None

    self.loaded_models: list[str] = []
    self._feature_extractor = FeatureExtractor(
      FeatureExtractionConfig(
        processed_data_path=self.config.processed_data_path,
        features_output_path=self.config.features_path,
      )
    )

  def load_all_models(self) -> list[str]:
    """Load every available trained model and preprocessing artifact."""
    logger.info("Loading trained models for attack prediction")

    self._load_preprocessing_artifacts()
    self._load_random_forest()
    self._load_isolation_forest()
    self._load_dbscan()
    self._load_cnn()
    self._prepare_isolation_forest_features()

    if not self.loaded_models:
      raise FileNotFoundError(
        "No trained models found. Train models before running prediction."
      )

    logger.info("Loaded models: %s", ", ".join(self.loaded_models))
    return self.loaded_models.copy()

  def _load_json_metadata(self, metadata_path: Path) -> dict[str, Any]:
    if not metadata_path.exists():
      return {}

    with open(metadata_path, "r", encoding="utf-8") as metadata_file:
      return json.load(metadata_file)

  def _load_preprocessing_artifacts(self) -> None:
    processed_path = Path(self.config.processed_data_path)
    scaler_path = processed_path / "scaler.pkl"
    label_encoder_path = processed_path / "label_encoder.pkl"
    metadata_path = processed_path / "metadata.json"

    if scaler_path.exists():
      self.scaler = joblib.load(scaler_path)

    if label_encoder_path.exists():
      self.label_encoder = joblib.load(label_encoder_path)
      self.label_classes = self.label_encoder.classes_.tolist()

    metadata = self._load_json_metadata(metadata_path)
    if metadata.get("feature_columns"):
      self.feature_columns = metadata["feature_columns"]
    if metadata.get("label_classes") and not self.label_classes:
      self.label_classes = metadata["label_classes"]

    self._feature_extractor.feature_columns = self.feature_columns
    self._feature_extractor.label_classes = self.label_classes

  def _load_random_forest(self) -> None:
    model_path = self.config.sklearn_model_path / "random_forest_model.pkl"
    metadata_path = self.config.sklearn_model_path / "random_forest_metadata.json"

    if not model_path.exists():
      logger.warning("Random Forest model not found at %s", model_path)
      return

    self.random_forest_model = joblib.load(model_path)
    metadata = self._load_json_metadata(metadata_path)
    if metadata.get("label_classes"):
      self.label_classes = metadata["label_classes"]
    if metadata.get("feature_names") and not self.feature_columns:
      self.feature_columns = metadata["feature_names"]

    self.loaded_models.append("random_forest")

  def _load_isolation_forest(self) -> None:
    model_path = self.config.sklearn_model_path / "isolation_forest_model.pkl"
    metadata_path = self.config.sklearn_model_path / "isolation_forest_metadata.json"

    if not model_path.exists():
      logger.warning("Isolation Forest model not found at %s", model_path)
      return

    self.isolation_forest_model = joblib.load(model_path)
    metadata = self._load_json_metadata(metadata_path)
    if metadata.get("label_classes") and not self.label_classes:
      self.label_classes = metadata["label_classes"]

    self.loaded_models.append("isolation_forest")

  def _load_dbscan(self) -> None:
    model_path = self.config.sklearn_model_path / "dbscan_model.pkl"
    train_labels_path = self.config.sklearn_model_path / "dbscan_train_labels.npy"
    reference_features_path = self.config.features_path / "dbscan" / "X_train.npy"
    pca_paths = [
      self.config.features_path / "dbscan" / "pca_model.pkl",
      self.config.sklearn_model_path / "dbscan_pca_model.pkl",
    ]

    if not model_path.exists():
      logger.warning("DBSCAN model not found at %s", model_path)
      return

    self.dbscan_model = joblib.load(model_path)

    for pca_path in pca_paths:
      if pca_path.exists():
        self.dbscan_pca_model = joblib.load(pca_path)
        break

    if reference_features_path.exists() and train_labels_path.exists():
      self.dbscan_reference_features = np.load(reference_features_path)
      self.dbscan_reference_labels = np.load(train_labels_path)
      self.dbscan_nearest_neighbors = NearestNeighbors(
        n_neighbors=1,
        metric=self.config.dbscan_metric,
      )
      self.dbscan_nearest_neighbors.fit(self.dbscan_reference_features)
    else:
      logger.warning(
        "DBSCAN reference features or labels missing. DBSCAN inference will be skipped."
      )
      self.dbscan_model = None
      return

    self.loaded_models.append("dbscan")

  def _load_cnn(self) -> None:
    model_path = self.config.tensorflow_model_path / "cnn_encrypted_traffic_model.keras"

    if not model_path.exists():
      logger.warning("CNN model not found at %s", model_path)
      return

    self.cnn_predictor = CNNPredictionHelper.from_artifacts(
      model_output_path=self.config.tensorflow_model_path
    )
    if self.cnn_predictor.label_classes and not self.label_classes:
      self.label_classes = self.cnn_predictor.label_classes

    self.loaded_models.append("cnn")

  def _prepare_isolation_forest_features(self) -> None:
    if not self.feature_columns:
      return

    selected_features = self._feature_extractor._match_feature_names(ISOLATION_FOREST_FEATURE_KEYWORDS)
    feature_indices = self._feature_extractor._get_feature_indices(selected_features)

    if len(feature_indices) < 10:
      self.isolation_feature_indices = list(range(len(self.feature_columns)))
    else:
      self.isolation_feature_indices = feature_indices

  def _normalize_features(self, features: np.ndarray) -> np.ndarray:
    if features.ndim == 1:
      features = features.reshape(1, -1)

    if features.ndim != 2:
      raise ValueError("Features must be a 1D or 2D array")

    if self.config.require_scaled_input or self.scaler is None:
      return features.astype(np.float32)

    return self.scaler.transform(features).astype(np.float32)

  def _lookup_feature_value(self, features: dict[str, Any], column: str) -> float:
    if column in features:
      return float(features[column])

    normalized_features = {
      str(key).lower(): value
      for key, value in features.items()
      if isinstance(value, (int, float, np.number))
    }
    return float(normalized_features.get(column.lower(), 0.0))

  def prepare_input(
    self,
    features: Union[np.ndarray, dict[str, Any], list[Any]],
    scale_raw_features: bool = True,
  ) -> np.ndarray:
    """Convert raw or scaled flow features into a model-ready matrix."""
    if isinstance(features, dict):
      if not self.feature_columns:
        raise ValueError("Feature columns are not loaded. Run load_all_models() first.")

      ordered_values = [
        self._lookup_feature_value(features, column)
        for column in self.feature_columns
      ]
      feature_matrix = np.array([ordered_values], dtype=np.float32)

      if scale_raw_features:
        return self._normalize_features(feature_matrix)

      return feature_matrix

    feature_matrix = np.asarray(features, dtype=np.float32)
    if feature_matrix.ndim == 1:
      feature_matrix = feature_matrix.reshape(1, -1)

    if feature_matrix.ndim != 2:
      raise ValueError("Features must be a 1D or 2D array")

    return feature_matrix.astype(np.float32)

  def _resolve_label(self, class_index: int) -> str:
    if self.label_classes and 0 <= class_index < len(self.label_classes):
      return str(self.label_classes[class_index])
    return str(class_index)

  def _is_attack_label(self, label: str) -> bool:
    normalized_label = label.strip().upper()
    return normalized_label not in {self.config.benign_label.upper(), "NORMAL"}

  def _threat_level(self, confidence: float, is_attack: bool) -> str:
    if not is_attack:
      return "low"

    if confidence >= 0.85:
      return "high"

    if confidence >= 0.6:
      return "medium"

    return "low"

  def _predict_random_forest(self, features: np.ndarray) -> Optional[ModelPrediction]:
    if self.random_forest_model is None:
      return None

    probabilities = self.random_forest_model.predict_proba(features)[0]
    predicted_index = int(np.argmax(probabilities))
    attack_label = self._resolve_label(predicted_index)
    confidence = float(probabilities[predicted_index])

    return ModelPrediction(
      model_name="random_forest",
      attack_label=attack_label,
      confidence=confidence,
      is_attack=self._is_attack_label(attack_label),
      details={
        "predicted_class_index": predicted_index,
        "probabilities": {
          self._resolve_label(index): float(value)
          for index, value in enumerate(probabilities)
        },
      },
    )

  def _predict_isolation_forest(self, features: np.ndarray) -> Optional[ModelPrediction]:
    if self.isolation_forest_model is None:
      return None

    isolation_features = self._feature_extractor._select_features_by_indices(
      features,
      self.isolation_feature_indices,
    )
    prediction = int(self.isolation_forest_model.predict(isolation_features)[0])
    decision_score = float(self.isolation_forest_model.decision_function(isolation_features)[0])
    anomaly_score = float(-decision_score)
    confidence = float(1.0 / (1.0 + np.exp(-anomaly_score)))

    is_anomaly = prediction == -1
    attack_label = self.config.anomaly_label if is_anomaly else self.config.benign_label

    return ModelPrediction(
      model_name="isolation_forest",
      attack_label=attack_label,
      confidence=confidence if is_anomaly else float(1.0 - confidence),
      is_attack=is_anomaly,
      details={
        "prediction": prediction,
        "decision_score": decision_score,
        "anomaly_score": anomaly_score,
      },
    )

  def _transform_dbscan_features(self, features: np.ndarray) -> np.ndarray:
    if self.dbscan_pca_model is not None:
      return self.dbscan_pca_model.transform(features)

    return features

  def _predict_dbscan(self, features: np.ndarray) -> Optional[ModelPrediction]:
    if (
      self.dbscan_nearest_neighbors is None
      or self.dbscan_reference_labels is None
    ):
      return None

    dbscan_features = self._transform_dbscan_features(features)
    distances, neighbor_indices = self.dbscan_nearest_neighbors.kneighbors(dbscan_features)
    cluster_id = int(self.dbscan_reference_labels[neighbor_indices[0][0]])
    neighbor_distance = float(distances[0][0])

    is_anomaly = cluster_id == -1
    attack_label = self.config.anomaly_label if is_anomaly else self.config.benign_label
    confidence = float(1.0 / (1.0 + neighbor_distance)) if is_anomaly else float(
      max(0.0, 1.0 - (neighbor_distance / (neighbor_distance + 1.0)))
    )

    return ModelPrediction(
      model_name="dbscan",
      attack_label=attack_label,
      confidence=confidence,
      is_attack=is_anomaly,
      details={
        "cluster_id": cluster_id,
        "neighbor_distance": neighbor_distance,
      },
    )

  def _predict_cnn(self, features: np.ndarray) -> Optional[ModelPrediction]:
    if self.cnn_predictor is None:
      return None

    cnn_result = self.cnn_predictor.predict_single(features)
    attack_label = cnn_result.predicted_label
    confidence = cnn_result.confidence

    return ModelPrediction(
      model_name="cnn",
      attack_label=attack_label,
      confidence=confidence,
      is_attack=self._is_attack_label(attack_label),
      details={
        "predicted_class_index": cnn_result.predicted_class_index,
        "probabilities": cnn_result.probabilities,
      },
    )

  def _ensemble_predictions(self, model_predictions: list[ModelPrediction]) -> tuple[str, float, bool]:
    label_scores: dict[str, float] = {}

    for prediction in model_predictions:
      weight = self.config.model_weights.get(prediction.model_name, 0.1)
      weighted_confidence = prediction.confidence * weight
      label_scores[prediction.attack_label] = (
        label_scores.get(prediction.attack_label, 0.0) + weighted_confidence
      )

    if not label_scores:
      return self.config.benign_label, 0.0, False

    attack_candidates = {
      label: score
      for label, score in label_scores.items()
      if self._is_attack_label(label)
    }

    if attack_candidates:
      attack_label = max(attack_candidates, key=attack_candidates.get)
      winning_score = attack_candidates[attack_label]
      total_attack_weight = sum(
        self.config.model_weights.get(prediction.model_name, 0.1)
        for prediction in model_predictions
        if prediction.attack_label == attack_label
      )
      confidence = float(winning_score / total_attack_weight) if total_attack_weight > 0 else winning_score
      return attack_label, min(confidence, 1.0), True

    benign_label = self.config.benign_label
    benign_score = label_scores.get(benign_label, 0.0)
    total_benign_weight = sum(
      self.config.model_weights.get(prediction.model_name, 0.1)
      for prediction in model_predictions
      if not prediction.is_attack
    )
    confidence = float(benign_score / total_benign_weight) if total_benign_weight > 0 else benign_score
    return benign_label, min(confidence, 1.0), False

  def predict(
    self,
    features: Union[np.ndarray, dict[str, Any], list[Any]],
  ) -> AttackPredictionResult:
    """Predict attack label and confidence for a single flow sample."""
    results = self.predict_batch(features)
    return results[0]

  def predict_batch(
    self,
    features: Union[np.ndarray, dict[str, Any], list[Any]],
  ) -> list[AttackPredictionResult]:
    """Predict attack labels and confidence for one or more flow samples."""
    if not self.loaded_models:
      self.load_all_models()

    feature_matrix = self.prepare_input(features)
    batch_results: list[AttackPredictionResult] = []

    for sample_index in range(len(feature_matrix)):
      sample = feature_matrix[sample_index].reshape(1, -1)
      model_predictions: list[ModelPrediction] = []

      random_forest_prediction = self._predict_random_forest(sample)
      if random_forest_prediction is not None:
        model_predictions.append(random_forest_prediction)

      isolation_forest_prediction = self._predict_isolation_forest(sample)
      if isolation_forest_prediction is not None:
        model_predictions.append(isolation_forest_prediction)

      dbscan_prediction = self._predict_dbscan(sample)
      if dbscan_prediction is not None:
        model_predictions.append(dbscan_prediction)

      cnn_prediction = self._predict_cnn(sample)
      if cnn_prediction is not None:
        model_predictions.append(cnn_prediction)

      attack_label, confidence, is_attack = self._ensemble_predictions(model_predictions)
      threat_level = self._threat_level(confidence, is_attack)

      batch_results.append(
        AttackPredictionResult(
          attack_label=attack_label,
          confidence=confidence,
          is_attack=is_attack,
          threat_level=threat_level,
          model_predictions=model_predictions,
          ensemble_method="weighted_confidence_vote",
        )
      )

    return batch_results


def load_predictor(
  sklearn_model_path: Optional[str] = None,
  tensorflow_model_path: Optional[str] = None,
  processed_data_path: Optional[str] = None,
  features_path: Optional[str] = None,
) -> AttackPredictor:
  """Create an AttackPredictor and load all available trained models."""
  config = PredictorConfig()

  if sklearn_model_path:
    config.sklearn_model_path = Path(sklearn_model_path)

  if tensorflow_model_path:
    config.tensorflow_model_path = Path(tensorflow_model_path)

  if processed_data_path:
    config.processed_data_path = Path(processed_data_path)

  if features_path:
    config.features_path = Path(features_path)

  predictor = AttackPredictor(config=config)
  predictor.load_all_models()
  return predictor


def predict_attack(
  features: Union[np.ndarray, dict[str, Any], list[Any]],
  sklearn_model_path: Optional[str] = None,
  tensorflow_model_path: Optional[str] = None,
  processed_data_path: Optional[str] = None,
  features_path: Optional[str] = None,
) -> AttackPredictionResult:
  """Convenience helper to load models and predict a single attack result."""
  predictor = load_predictor(
    sklearn_model_path=sklearn_model_path,
    tensorflow_model_path=tensorflow_model_path,
    processed_data_path=processed_data_path,
    features_path=features_path,
  )
  return predictor.predict(features)


if __name__ == "__main__":
  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
  )

  processed_path = Path(DEFAULT_PROCESSED_DATA_PATH)
  if (processed_path / "X_test.npy").exists():
    sample_features = np.load(processed_path / "X_test.npy")[0]
    result = predict_attack(sample_features)
    print(json.dumps(result.to_dict(), indent=2))
  else:
    logger.error("Processed test data not found. Run preprocessing before prediction.")
