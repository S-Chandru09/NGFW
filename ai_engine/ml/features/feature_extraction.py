"""
Feature extraction for multiple ML models used in the AI-NGFW threat detection pipeline.

Supports:
- Random Forest: tabular flow features
- Isolation Forest: anomaly-focused tabular features
- DBSCAN: PCA-reduced density-clustering features
- CNN: reshaped tensor features for deep learning
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
from sklearn.decomposition import PCA

logger = logging.getLogger("ai-engine.feature_extraction")

DEFAULT_PROCESSED_DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "processed" / "cicids2017"
DEFAULT_FEATURES_OUTPUT_PATH = Path(__file__).resolve().parents[2] / "data" / "processed" / "features"

ISOLATION_FOREST_FEATURE_KEYWORDS = [
  "flow_duration",
  "total_fwd_packets",
  "total_backward_packets",
  "total_length_of_fwd_packets",
  "total_length_of_bwd_packets",
  "fwd_packet_length_max",
  "fwd_packet_length_min",
  "fwd_packet_length_mean",
  "bwd_packet_length_max",
  "bwd_packet_length_min",
  "bwd_packet_length_mean",
  "flow_bytes_s",
  "flow_packets_s",
  "flow_iat_mean",
  "flow_iat_std",
  "flow_iat_max",
  "flow_iat_min",
  "fwd_iat_total",
  "fwd_iat_mean",
  "fwd_iat_std",
  "bwd_iat_total",
  "bwd_iat_mean",
  "bwd_iat_std",
  "packet_length_mean",
  "packet_length_std",
  "packet_length_variance",
  "fin_flag_count",
  "syn_flag_count",
  "rst_flag_count",
  "psh_flag_count",
  "ack_flag_count",
  "urg_flag_count",
  "cwe_flag_count",
  "ece_flag_count",
  "down_up_ratio",
  "average_packet_size",
  "subflow_fwd_packets",
  "subflow_bwd_packets",
  "subflow_fwd_bytes",
  "subflow_bwd_bytes",
  "destination_port",
]

CNN_DEFAULT_GRID_SIZE = 9


@dataclass
class FeatureExtractionConfig:
  processed_data_path: Path = DEFAULT_PROCESSED_DATA_PATH
  features_output_path: Path = DEFAULT_FEATURES_OUTPUT_PATH
  dbscan_pca_components: int = 15
  cnn_grid_height: int = CNN_DEFAULT_GRID_SIZE
  cnn_grid_width: int = CNN_DEFAULT_GRID_SIZE
  random_state: int = 42
  save_artifacts: bool = True


@dataclass
class ModelFeatureSet:
  model_name: str
  X_train: np.ndarray
  X_test: np.ndarray
  y_train: Optional[np.ndarray] = None
  y_test: Optional[np.ndarray] = None
  feature_names: Optional[list[str]] = None
  metadata: Optional[dict] = None


@dataclass
class FeatureExtractionReport:
  random_forest_feature_count: int
  isolation_forest_feature_count: int
  dbscan_feature_count: int
  cnn_input_shape: tuple[int, ...]
  train_samples: int
  test_samples: int
  class_count: int
  processed_at: str


class FeatureExtractor:
  def __init__(self, config: Optional[FeatureExtractionConfig] = None) -> None:
    self.config = config or FeatureExtractionConfig()
    self.feature_columns: list[str] = []
    self.label_classes: list[str] = []
    self.pca_model: Optional[PCA] = None
    self.report: Optional[FeatureExtractionReport] = None

  def load_preprocessed_data(self) -> dict[str, object]:
    processed_path = Path(self.config.processed_data_path)

    if not processed_path.exists():
      raise FileNotFoundError(
        f"Processed dataset not found at {processed_path}. "
        "Run preprocessing.py first."
      )

    required_files = ["X_train.npy", "X_test.npy", "y_train.npy", "y_test.npy"]
    for file_name in required_files:
      if not (processed_path / file_name).exists():
        raise FileNotFoundError(f"Missing processed file: {processed_path / file_name}")

    data = {
      "X_train": np.load(processed_path / "X_train.npy"),
      "X_test": np.load(processed_path / "X_test.npy"),
      "y_train": np.load(processed_path / "y_train.npy"),
      "y_test": np.load(processed_path / "y_test.npy"),
    }

    metadata_file = processed_path / "metadata.json"
    if metadata_file.exists():
      with open(metadata_file, "r", encoding="utf-8") as file:
        metadata = json.load(file)
      self.feature_columns = metadata.get("feature_columns", [])
      self.label_classes = metadata.get("label_classes", [])
      data["metadata"] = metadata
    else:
      feature_count = data["X_train"].shape[1]
      self.feature_columns = [f"feature_{index}" for index in range(feature_count)]

    logger.info(
      "Loaded preprocessed data | train=%s | test=%s | features=%s",
      len(data["X_train"]),
      len(data["X_test"]),
      data["X_train"].shape[1],
    )
    return data

  def _match_feature_names(self, keywords: list[str]) -> list[str]:
    matched_features: list[str] = []

    for column in self.feature_columns:
      normalized_column = column.lower()
      if any(keyword in normalized_column for keyword in keywords):
        matched_features.append(column)

    return matched_features

  def _get_feature_indices(self, selected_features: list[str]) -> list[int]:
    indices: list[int] = []

    for feature_name in selected_features:
      if feature_name in self.feature_columns:
        indices.append(self.feature_columns.index(feature_name))

    return indices

  def _select_features_by_indices(
    self,
    feature_matrix: np.ndarray,
    feature_indices: list[int],
  ) -> np.ndarray:
    if not feature_indices:
      return feature_matrix

    return feature_matrix[:, feature_indices]

  def extract_random_forest_features(
    self,
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
  ) -> ModelFeatureSet:
    logger.info("Extracting Random Forest features")

    return ModelFeatureSet(
      model_name="random_forest",
      X_train=X_train,
      X_test=X_test,
      y_train=y_train,
      y_test=y_test,
      feature_names=self.feature_columns.copy(),
      metadata={
        "model_type": "supervised",
        "algorithm": "RandomForestClassifier",
        "input_shape": list(X_train.shape[1:]),
        "feature_count": int(X_train.shape[1]),
      },
    )

  def extract_isolation_forest_features(
    self,
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: Optional[np.ndarray] = None,
    y_test: Optional[np.ndarray] = None,
  ) -> ModelFeatureSet:
    logger.info("Extracting Isolation Forest features")

    selected_features = self._match_feature_names(ISOLATION_FOREST_FEATURE_KEYWORDS)
    feature_indices = self._get_feature_indices(selected_features)

    if len(feature_indices) < 10:
      logger.warning(
        "Isolation Forest keyword match found fewer than 10 features. Using full feature set."
      )
      isolation_X_train = X_train
      isolation_X_test = X_test
      selected_feature_names = self.feature_columns.copy()
    else:
      isolation_X_train = self._select_features_by_indices(X_train, feature_indices)
      isolation_X_test = self._select_features_by_indices(X_test, feature_indices)
      selected_feature_names = [self.feature_columns[index] for index in feature_indices]

    return ModelFeatureSet(
      model_name="isolation_forest",
      X_train=isolation_X_train,
      X_test=isolation_X_test,
      y_train=y_train,
      y_test=y_test,
      feature_names=selected_feature_names,
      metadata={
        "model_type": "unsupervised",
        "algorithm": "IsolationForest",
        "input_shape": list(isolation_X_train.shape[1:]),
        "feature_count": int(isolation_X_train.shape[1]),
        "description": "Anomaly-focused flow statistics for outlier detection",
      },
    )

  def extract_dbscan_features(
    self,
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: Optional[np.ndarray] = None,
    y_test: Optional[np.ndarray] = None,
  ) -> ModelFeatureSet:
    logger.info("Extracting DBSCAN features with PCA dimensionality reduction")

    n_components = min(
      self.config.dbscan_pca_components,
      X_train.shape[0],
      X_train.shape[1],
    )

    self.pca_model = PCA(
      n_components=n_components,
      random_state=self.config.random_state,
    )

    dbscan_X_train = self.pca_model.fit_transform(X_train)
    dbscan_X_test = self.pca_model.transform(X_test)

    pca_feature_names = [f"pca_component_{index + 1}" for index in range(n_components)]

    return ModelFeatureSet(
      model_name="dbscan",
      X_train=dbscan_X_train,
      X_test=dbscan_X_test,
      y_train=y_train,
      y_test=y_test,
      feature_names=pca_feature_names,
      metadata={
        "model_type": "unsupervised",
        "algorithm": "DBSCAN",
        "input_shape": list(dbscan_X_train.shape[1:]),
        "feature_count": int(dbscan_X_train.shape[1]),
        "pca_components": n_components,
        "explained_variance_ratio": self.pca_model.explained_variance_ratio_.tolist(),
        "description": "PCA-reduced features for density-based clustering",
      },
    )

  def reshape_for_cnn(
    self,
    feature_matrix: np.ndarray,
    grid_height: Optional[int] = None,
    grid_width: Optional[int] = None,
  ) -> np.ndarray:
    height = grid_height or self.config.cnn_grid_height
    width = grid_width or self.config.cnn_grid_width
    target_size = height * width
    sample_count, feature_count = feature_matrix.shape

    if feature_count > target_size:
      trimmed_matrix = feature_matrix[:, :target_size]
    else:
      padding_size = target_size - feature_count
      padding = np.zeros((sample_count, padding_size), dtype=feature_matrix.dtype)
      trimmed_matrix = np.concatenate([feature_matrix, padding], axis=1)

    cnn_input = trimmed_matrix.reshape(sample_count, height, width, 1)
    return cnn_input

  def extract_cnn_features(
    self,
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
  ) -> ModelFeatureSet:
    logger.info("Extracting CNN tensor features")

    cnn_X_train = self.reshape_for_cnn(X_train)
    cnn_X_test = self.reshape_for_cnn(X_test)

    return ModelFeatureSet(
      model_name="cnn",
      X_train=cnn_X_train,
      X_test=cnn_X_test,
      y_train=y_train,
      y_test=y_test,
      feature_names=self.feature_columns.copy(),
      metadata={
        "model_type": "supervised",
        "algorithm": "Convolutional Neural Network",
        "input_shape": list(cnn_X_train.shape[1:]),
        "grid_height": self.config.cnn_grid_height,
        "grid_width": self.config.cnn_grid_width,
        "channels": 1,
        "original_feature_count": int(X_train.shape[1]),
        "description": "Reshaped flow feature tensors for CNN training",
      },
    )

  def extract_all_features(self) -> dict[str, ModelFeatureSet]:
    processed_data = self.load_preprocessed_data()

    X_train = processed_data["X_train"]
    X_test = processed_data["X_test"]
    y_train = processed_data["y_train"]
    y_test = processed_data["y_test"]

    feature_sets = {
      "random_forest": self.extract_random_forest_features(X_train, X_test, y_train, y_test),
      "isolation_forest": self.extract_isolation_forest_features(X_train, X_test, y_train, y_test),
      "dbscan": self.extract_dbscan_features(X_train, X_test, y_train, y_test),
      "cnn": self.extract_cnn_features(X_train, X_test, y_train, y_test),
    }

    self.report = FeatureExtractionReport(
      random_forest_feature_count=int(feature_sets["random_forest"].X_train.shape[1]),
      isolation_forest_feature_count=int(feature_sets["isolation_forest"].X_train.shape[1]),
      dbscan_feature_count=int(feature_sets["dbscan"].X_train.shape[1]),
      cnn_input_shape=tuple(feature_sets["cnn"].X_train.shape[1:]),
      train_samples=int(X_train.shape[0]),
      test_samples=int(X_test.shape[0]),
      class_count=len(self.label_classes) if self.label_classes else int(len(np.unique(y_train))),
      processed_at=datetime.now(timezone.utc).isoformat(),
    )

    self.save_feature_sets(feature_sets)
    return feature_sets

  def save_feature_sets(self, feature_sets: dict[str, ModelFeatureSet]) -> Path:
    output_path = Path(self.config.features_output_path)
    output_path.mkdir(parents=True, exist_ok=True)

    for model_name, feature_set in feature_sets.items():
      model_path = output_path / model_name
      model_path.mkdir(parents=True, exist_ok=True)

      np.save(model_path / "X_train.npy", feature_set.X_train)
      np.save(model_path / "X_test.npy", feature_set.X_test)

      if feature_set.y_train is not None:
        np.save(model_path / "y_train.npy", feature_set.y_train)

      if feature_set.y_test is not None:
        np.save(model_path / "y_test.npy", feature_set.y_test)

      metadata = {
        "model_name": feature_set.model_name,
        "feature_names": feature_set.feature_names,
        "metadata": feature_set.metadata,
      }

      with open(model_path / "metadata.json", "w", encoding="utf-8") as metadata_file:
        json.dump(metadata, metadata_file, indent=2)

      logger.info("Saved %s features to %s", model_name, model_path)

    if self.config.save_artifacts and self.pca_model is not None:
      joblib.dump(self.pca_model, output_path / "dbscan" / "pca_model.pkl")

    summary = {
      "report": asdict(self.report) if self.report else {},
      "models": list(feature_sets.keys()),
      "output_path": str(output_path),
    }

    with open(output_path / "feature_extraction_summary.json", "w", encoding="utf-8") as summary_file:
      json.dump(summary, summary_file, indent=2)

    logger.info("Feature extraction summary saved to %s", output_path)
    return output_path

  @staticmethod
  def load_feature_set(model_name: str, features_output_path: Optional[Path] = None) -> ModelFeatureSet:
    output_path = Path(features_output_path or DEFAULT_FEATURES_OUTPUT_PATH)
    model_path = output_path / model_name

    if not model_path.exists():
      raise FileNotFoundError(f"Feature set not found for model: {model_name}")

    feature_set = ModelFeatureSet(
      model_name=model_name,
      X_train=np.load(model_path / "X_train.npy"),
      X_test=np.load(model_path / "X_test.npy"),
    )

    if (model_path / "y_train.npy").exists():
      feature_set.y_train = np.load(model_path / "y_train.npy")

    if (model_path / "y_test.npy").exists():
      feature_set.y_test = np.load(model_path / "y_test.npy")

    metadata_file = model_path / "metadata.json"
    if metadata_file.exists():
      with open(metadata_file, "r", encoding="utf-8") as file:
        metadata = json.load(file)
      feature_set.feature_names = metadata.get("feature_names")
      feature_set.metadata = metadata.get("metadata")

    logger.info("Loaded feature set for %s from %s", model_name, model_path)
    return feature_set


def run_feature_extraction(
  processed_data_path: Optional[str] = None,
  features_output_path: Optional[str] = None,
  dbscan_pca_components: int = 15,
  cnn_grid_height: int = CNN_DEFAULT_GRID_SIZE,
  cnn_grid_width: int = CNN_DEFAULT_GRID_SIZE,
) -> dict[str, ModelFeatureSet]:
  config = FeatureExtractionConfig()

  if processed_data_path:
    config.processed_data_path = Path(processed_data_path)

  if features_output_path:
    config.features_output_path = Path(features_output_path)

  config.dbscan_pca_components = dbscan_pca_components
  config.cnn_grid_height = cnn_grid_height
  config.cnn_grid_width = cnn_grid_width

  extractor = FeatureExtractor(config=config)
  feature_sets = extractor.extract_all_features()

  logger.info("Feature extraction completed for all models")
  for model_name, feature_set in feature_sets.items():
    logger.info(
      "%s | train_shape=%s | test_shape=%s",
      model_name,
      feature_set.X_train.shape,
      feature_set.X_test.shape,
    )

  return feature_sets


if __name__ == "__main__":
  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
  )
  run_feature_extraction()
