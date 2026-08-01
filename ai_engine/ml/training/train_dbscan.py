"""
Train DBSCAN clustering model for CICIDS2017 traffic pattern analysis.

Loads PCA-reduced features, performs density-based clustering,
generates visualizations, and saves clustering results.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import joblib
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
from sklearn.metrics import (
  adjusted_rand_score,
  calinski_harabasz_score,
  davies_bouldin_score,
  normalized_mutual_info_score,
  silhouette_score,
)
from sklearn.neighbors import NearestNeighbors

from ml.features.feature_extraction import DEFAULT_FEATURES_OUTPUT_PATH, FeatureExtractor

logger = logging.getLogger("ai-engine.train_dbscan")

DEFAULT_MODEL_OUTPUT_PATH = Path(__file__).resolve().parents[1] / "models" / "sklearn"
DEFAULT_PROCESSED_DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "processed" / "cicids2017"
DEFAULT_MODEL_FILENAME = "dbscan_model.pkl"
DEFAULT_METRICS_FILENAME = "dbscan_metrics.json"
DEFAULT_METADATA_FILENAME = "dbscan_metadata.json"
DEFAULT_TRAIN_LABELS_FILENAME = "dbscan_train_labels.npy"
DEFAULT_TEST_LABELS_FILENAME = "dbscan_test_labels.npy"
DEFAULT_BENIGN_LABEL = "BENIGN"
DEFAULT_VISUALIZATION_DIRNAME = "visualizations"
DEFAULT_CLUSTER_PLOT_FILENAME = "dbscan_clusters_train.png"
DEFAULT_TRUE_LABEL_PLOT_FILENAME = "dbscan_true_labels_train.png"
DEFAULT_TEST_CLUSTER_PLOT_FILENAME = "dbscan_clusters_test.png"


@dataclass
class DBSCANTrainingConfig:
  features_path: Path = DEFAULT_FEATURES_OUTPUT_PATH
  processed_data_path: Path = DEFAULT_PROCESSED_DATA_PATH
  model_output_path: Path = DEFAULT_MODEL_OUTPUT_PATH
  model_filename: str = DEFAULT_MODEL_FILENAME
  metrics_filename: str = DEFAULT_METRICS_FILENAME
  metadata_filename: str = DEFAULT_METADATA_FILENAME
  train_labels_filename: str = DEFAULT_TRAIN_LABELS_FILENAME
  test_labels_filename: str = DEFAULT_TEST_LABELS_FILENAME
  visualization_dirname: str = DEFAULT_VISUALIZATION_DIRNAME
  cluster_plot_filename: str = DEFAULT_CLUSTER_PLOT_FILENAME
  true_label_plot_filename: str = DEFAULT_TRUE_LABEL_PLOT_FILENAME
  test_cluster_plot_filename: str = DEFAULT_TEST_CLUSTER_PLOT_FILENAME
  eps: float = 0.8
  min_samples: int = 5
  metric: str = "euclidean"
  algorithm: str = "auto"
  leaf_size: int = 30
  n_jobs: int = -1
  random_state: int = 42
  benign_label: str = DEFAULT_BENIGN_LABEL
  max_clustering_samples: Optional[int] = 25000
  max_evaluation_samples: int = 10000
  max_visualization_samples: int = 15000
  dbscan_pca_components: int = 15


@dataclass
class DBSCANTrainingReport:
  model_name: str
  algorithm: str
  dataset: str
  train_samples: int
  test_samples: int
  feature_count: int
  cluster_count: int
  noise_count: int
  metrics: dict
  cluster_distribution: dict
  visualization_paths: list[str]
  model_path: str
  metrics_path: str
  metadata_path: str
  train_labels_path: str
  test_labels_path: str
  trained_at: str


class DBSCANTrainer:
  def __init__(self, config: Optional[DBSCANTrainingConfig] = None) -> None:
    self.config = config or DBSCANTrainingConfig()
    self.model: Optional[DBSCAN] = None
    self.pca_model: Optional[PCA] = None
    self.feature_names: list[str] = []
    self.label_classes: list[str] = []
    self.benign_label_index: Optional[int] = None
    self.train_cluster_labels: Optional[np.ndarray] = None
    self.test_cluster_labels: Optional[np.ndarray] = None
    self.report: Optional[DBSCANTrainingReport] = None

  def load_training_data(self) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    logger.info("Loading DBSCAN feature set")

    try:
      feature_set = FeatureExtractor.load_feature_set(
        model_name="dbscan",
        features_output_path=self.config.features_path,
      )
      X_train = feature_set.X_train
      X_test = feature_set.X_test
      y_train = feature_set.y_train
      y_test = feature_set.y_test
      self.feature_names = feature_set.feature_names or []

      pca_model_path = Path(self.config.features_path) / "dbscan" / "pca_model.pkl"
      if pca_model_path.exists():
        self.pca_model = joblib.load(pca_model_path)

    except FileNotFoundError:
      logger.warning("DBSCAN feature set not found. Building PCA features from processed dataset.")
      processed_path = Path(self.config.processed_data_path)

      raw_X_train = np.load(processed_path / "X_train.npy")
      raw_X_test = np.load(processed_path / "X_test.npy")
      y_train = np.load(processed_path / "y_train.npy")
      y_test = np.load(processed_path / "y_test.npy")

      metadata_file = processed_path / "metadata.json"
      if metadata_file.exists():
        with open(metadata_file, "r", encoding="utf-8") as file:
          metadata = json.load(file)
        self.feature_names = metadata.get("feature_columns", [])
        self.label_classes = metadata.get("label_classes", [])

      n_components = min(
        self.config.dbscan_pca_components,
        raw_X_train.shape[0],
        raw_X_train.shape[1],
      )

      self.pca_model = PCA(
        n_components=n_components,
        random_state=self.config.random_state,
      )
      X_train = self.pca_model.fit_transform(raw_X_train)
      X_test = self.pca_model.transform(raw_X_test)
      self.feature_names = [f"pca_component_{index + 1}" for index in range(n_components)]

    if y_train is None or y_test is None:
      raise ValueError("Labels are required for DBSCAN evaluation")

    self._load_label_classes()
    logger.info(
      "Training data loaded | train=%s | test=%s | features=%s",
      len(X_train),
      len(X_test),
      X_train.shape[1],
    )
    return X_train, X_test, y_train, y_test

  def _load_label_classes(self) -> None:
    if self.label_classes:
      self._set_benign_label_index()
      return

    label_encoder_path = Path(self.config.processed_data_path) / "label_encoder.pkl"
    if label_encoder_path.exists():
      label_encoder = joblib.load(label_encoder_path)
      self.label_classes = label_encoder.classes_.tolist()
      self._set_benign_label_index()
      return

    metadata_file = Path(self.config.processed_data_path) / "metadata.json"
    if metadata_file.exists():
      with open(metadata_file, "r", encoding="utf-8") as file:
        metadata = json.load(file)
      self.label_classes = metadata.get("label_classes", [])
      self._set_benign_label_index()

  def _set_benign_label_index(self) -> None:
    if not self.label_classes:
      self.benign_label_index = 0
      return

    normalized_labels = [label.upper() for label in self.label_classes]
    benign_label = self.config.benign_label.upper()

    if benign_label in normalized_labels:
      self.benign_label_index = normalized_labels.index(benign_label)
    else:
      self.benign_label_index = 0
      logger.warning(
        "Benign label '%s' not found in label classes. Using index 0 as benign.",
        self.config.benign_label,
      )

  def _convert_labels_to_binary(self, labels: np.ndarray) -> np.ndarray:
    if self.benign_label_index is None:
      self._set_benign_label_index()

    return np.where(labels == self.benign_label_index, 0, 1).astype(int)

  def _subsample_for_clustering(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    sample_count = len(X)

    if self.config.max_clustering_samples is None or sample_count <= self.config.max_clustering_samples:
      return X, np.arange(sample_count)

    rng = np.random.default_rng(self.config.random_state)
    selected_indices = rng.choice(
      sample_count,
      size=self.config.max_clustering_samples,
      replace=False,
    )
    selected_indices = np.sort(selected_indices)
    logger.info(
      "Subsampled training data for DBSCAN fit | original=%s | used=%s",
      sample_count,
      len(selected_indices),
    )
    return X[selected_indices], selected_indices

  def _subsample_for_evaluation(
    self,
    features: np.ndarray,
    labels: np.ndarray,
  ) -> tuple[np.ndarray, np.ndarray]:
    sample_count = len(features)
    max_samples = self.config.max_evaluation_samples

    if sample_count <= max_samples:
      return features, labels

    rng = np.random.default_rng(self.config.random_state)
    selected_indices = rng.choice(sample_count, size=max_samples, replace=False)
    logger.info(
      "Subsampled data for DBSCAN evaluation metrics | original=%s | used=%s",
      sample_count,
      max_samples,
    )
    return features[selected_indices], labels[selected_indices]

  def build_model(self) -> DBSCAN:
    return DBSCAN(
      eps=self.config.eps,
      min_samples=self.config.min_samples,
      metric=self.config.metric,
      algorithm=self.config.algorithm,
      leaf_size=self.config.leaf_size,
      n_jobs=self.config.n_jobs,
    )

  def _assign_labels_with_nearest_neighbors(
    self,
    reference_features: np.ndarray,
    reference_labels: np.ndarray,
    target_features: np.ndarray,
  ) -> np.ndarray:
    nearest_neighbors = NearestNeighbors(n_neighbors=1, metric=self.config.metric, n_jobs=self.config.n_jobs)
    nearest_neighbors.fit(reference_features)
    _, neighbor_indices = nearest_neighbors.kneighbors(target_features)
    return reference_labels[neighbor_indices.ravel()]

  def cluster(self, X_train: np.ndarray, X_test: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    logger.info("Running DBSCAN clustering")

    clustering_features, clustering_indices = self._subsample_for_clustering(X_train)
    self.model = self.build_model()
    sampled_labels = self.model.fit_predict(clustering_features)

    if len(clustering_indices) == len(X_train):
      train_labels = sampled_labels
    else:
      reference_features = X_train[clustering_indices]
      train_labels = self._assign_labels_with_nearest_neighbors(
        reference_features=reference_features,
        reference_labels=sampled_labels,
        target_features=X_train,
      )

    test_labels = self._assign_labels_with_nearest_neighbors(
      reference_features=X_train,
      reference_labels=train_labels,
      target_features=X_test,
    )

    self.train_cluster_labels = train_labels
    self.test_cluster_labels = test_labels

    unique_clusters = np.unique(train_labels)
    cluster_count = int(len(unique_clusters[unique_clusters != -1]))
    noise_count = int(np.sum(train_labels == -1))

    logger.info(
      "DBSCAN clustering completed | clusters=%s | noise_points=%s",
      cluster_count,
      noise_count,
    )
    return train_labels, test_labels

  def _build_cluster_distribution(self, cluster_labels: np.ndarray) -> dict:
    unique_labels, counts = np.unique(cluster_labels, return_counts=True)
    distribution: dict[str, int] = {}

    for label, count in zip(unique_labels, counts):
      key = "noise" if label == -1 else f"cluster_{int(label)}"
      distribution[key] = int(count)

    return distribution

  def evaluate(
    self,
    X_train: np.ndarray,
    y_train: np.ndarray,
    train_labels: np.ndarray,
    test_labels: np.ndarray,
    y_test: np.ndarray,
  ) -> dict:
    if self.model is None:
      raise ValueError("Model has not been trained yet")

    logger.info("Evaluating DBSCAN clustering results")

    unique_clusters = np.unique(train_labels)
    cluster_count = int(len(unique_clusters[unique_clusters != -1]))
    noise_count = int(np.sum(train_labels == -1))
    noise_ratio = noise_count / len(train_labels) if len(train_labels) > 0 else 0.0

    metrics: dict[str, float | int | None] = {
      "cluster_count": cluster_count,
      "noise_count": noise_count,
      "noise_ratio": float(noise_ratio),
      "train_samples": int(len(train_labels)),
      "test_samples": int(len(test_labels)),
    }

    non_noise_mask = train_labels != -1
    if np.sum(non_noise_mask) > 1 and cluster_count > 1:
      evaluation_features, evaluation_labels = self._subsample_for_evaluation(
        X_train[non_noise_mask],
        train_labels[non_noise_mask],
      )
      try:
        metrics["silhouette_score"] = float(
          silhouette_score(evaluation_features, evaluation_labels)
        )
      except ValueError:
        metrics["silhouette_score"] = None

      try:
        metrics["calinski_harabasz_score"] = float(
          calinski_harabasz_score(evaluation_features, evaluation_labels)
        )
      except ValueError:
        metrics["calinski_harabasz_score"] = None

      try:
        metrics["davies_bouldin_score"] = float(
          davies_bouldin_score(evaluation_features, evaluation_labels)
        )
      except ValueError:
        metrics["davies_bouldin_score"] = None
    else:
      metrics["silhouette_score"] = None
      metrics["calinski_harabasz_score"] = None
      metrics["davies_bouldin_score"] = None

    metrics["adjusted_rand_index"] = float(adjusted_rand_score(y_train, train_labels))
    metrics["normalized_mutual_info"] = float(normalized_mutual_info_score(y_train, train_labels))

    y_train_binary = self._convert_labels_to_binary(y_train)
    y_test_binary = self._convert_labels_to_binary(y_test)
    train_anomaly_predictions = np.where(train_labels == -1, 1, 0)
    test_anomaly_predictions = np.where(test_labels == -1, 1, 0)

    metrics["train_anomaly_detection_rate"] = float(
      self._safe_detection_rate(y_train_binary, train_anomaly_predictions)
    )
    metrics["test_anomaly_detection_rate"] = float(
      self._safe_detection_rate(y_test_binary, test_anomaly_predictions)
    )
    metrics["train_noise_as_anomaly_ratio"] = float(np.mean(train_anomaly_predictions))
    metrics["test_noise_as_anomaly_ratio"] = float(np.mean(test_anomaly_predictions))

    return {
      "metrics": metrics,
      "train_cluster_distribution": self._build_cluster_distribution(train_labels),
      "test_cluster_distribution": self._build_cluster_distribution(test_labels),
    }

  def _safe_detection_rate(self, y_true_binary: np.ndarray, y_pred_binary: np.ndarray) -> float:
    true_anomalies = int(np.sum(y_true_binary == 1))
    if true_anomalies == 0:
      return 0.0

    true_positives = int(np.sum((y_true_binary == 1) & (y_pred_binary == 1)))
    return true_positives / true_anomalies

  def _subsample_for_visualization(
    self,
    features: np.ndarray,
    cluster_labels: np.ndarray,
    true_labels: Optional[np.ndarray] = None,
  ) -> tuple[np.ndarray, np.ndarray, Optional[np.ndarray]]:
    sample_count = len(features)
    max_samples = self.config.max_visualization_samples

    if sample_count <= max_samples:
      return features, cluster_labels, true_labels

    rng = np.random.default_rng(self.config.random_state)
    selected_indices = rng.choice(sample_count, size=max_samples, replace=False)

    sampled_true_labels = true_labels[selected_indices] if true_labels is not None else None
    return features[selected_indices], cluster_labels[selected_indices], sampled_true_labels

  def _plot_scatter(
    self,
    features: np.ndarray,
    labels: np.ndarray,
    title: str,
    output_path: Path,
    label_name: str,
  ) -> Path:
    if features.shape[1] < 2:
      raise ValueError("At least two features are required for 2D visualization")

    x_values = features[:, 0]
    y_values = features[:, 1]
    unique_labels = np.unique(labels)

    plt.figure(figsize=(12, 8))
    color_map = plt.cm.get_cmap("tab20", max(len(unique_labels), 1))

    for index, label in enumerate(unique_labels):
      mask = labels == label
      display_label = "noise" if label == -1 else f"{label_name} {int(label)}"
      color = "#7f7f7f" if label == -1 else color_map(index % 20)
      plt.scatter(
        x_values[mask],
        y_values[mask],
        s=8,
        alpha=0.65,
        c=[color],
        label=display_label,
      )

    x_axis = self.feature_names[0] if self.feature_names else "Component 1"
    y_axis = self.feature_names[1] if len(self.feature_names) > 1 else "Component 2"

    plt.xlabel(x_axis)
    plt.ylabel(y_axis)
    plt.title(title)
    plt.legend(loc="best", fontsize=8, markerscale=2)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()

    logger.info("Saved visualization to %s", output_path)
    return output_path

  def visualize(
    self,
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    train_labels: np.ndarray,
    test_labels: np.ndarray,
  ) -> list[str]:
    logger.info("Generating DBSCAN visualizations")

    visualization_dir = Path(self.config.model_output_path) / self.config.visualization_dirname
    visualization_dir.mkdir(parents=True, exist_ok=True)

    train_features, train_clusters, train_true_labels = self._subsample_for_visualization(
      X_train,
      train_labels,
      y_train,
    )
    test_features, test_clusters, _ = self._subsample_for_visualization(
      X_test,
      test_labels,
    )

    train_cluster_plot = self._plot_scatter(
      features=train_features,
      labels=train_clusters,
      title="DBSCAN Clusters (Training Set)",
      output_path=visualization_dir / self.config.cluster_plot_filename,
      label_name="Cluster",
    )

    train_true_label_plot = self._plot_scatter(
      features=train_features,
      labels=train_true_labels,
      title="True Labels (Training Set)",
      output_path=visualization_dir / self.config.true_label_plot_filename,
      label_name="Class",
    )

    test_cluster_plot = self._plot_scatter(
      features=test_features,
      labels=test_clusters,
      title="DBSCAN Clusters (Test Set)",
      output_path=visualization_dir / self.config.test_cluster_plot_filename,
      label_name="Cluster",
    )

    return [
      str(train_cluster_plot),
      str(train_true_label_plot),
      str(test_cluster_plot),
    ]

  def save_model(self) -> Path:
    if self.model is None:
      raise ValueError("Model has not been trained yet")

    output_path = Path(self.config.model_output_path)
    output_path.mkdir(parents=True, exist_ok=True)

    model_path = output_path / self.config.model_filename
    joblib.dump(self.model, model_path)
    logger.info("Saved DBSCAN model to %s", model_path)
    return model_path

  def save_results(
    self,
    evaluation_results: dict,
    visualization_paths: list[str],
    X_train: np.ndarray,
    X_test: np.ndarray,
    train_labels: np.ndarray,
    test_labels: np.ndarray,
  ) -> DBSCANTrainingReport:
    model_path = self.save_model()
    output_path = Path(self.config.model_output_path)
    output_path.mkdir(parents=True, exist_ok=True)

    train_labels_path = output_path / self.config.train_labels_filename
    test_labels_path = output_path / self.config.test_labels_filename
    np.save(train_labels_path, train_labels)
    np.save(test_labels_path, test_labels)

    if self.pca_model is not None:
      joblib.dump(self.pca_model, output_path / "dbscan_pca_model.pkl")

    metrics_payload = {
      "model_name": "dbscan",
      "algorithm": "DBSCAN",
      "dataset": "CICIDS2017",
      "task": "density_clustering",
      "metrics": evaluation_results["metrics"],
      "train_cluster_distribution": evaluation_results["train_cluster_distribution"],
      "test_cluster_distribution": evaluation_results["test_cluster_distribution"],
      "train_samples": int(len(X_train)),
      "test_samples": int(len(X_test)),
      "feature_count": int(X_train.shape[1]),
      "visualization_paths": visualization_paths,
      "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }

    metrics_path = output_path / self.config.metrics_filename
    with open(metrics_path, "w", encoding="utf-8") as metrics_file:
      json.dump(metrics_payload, metrics_file, indent=2)

    metadata_payload = {
      "model_name": "dbscan",
      "algorithm": "DBSCAN",
      "dataset": "CICIDS2017",
      "task": "density_clustering",
      "model_path": str(model_path),
      "train_labels_path": str(train_labels_path),
      "test_labels_path": str(test_labels_path),
      "feature_names": self.feature_names,
      "label_classes": self.label_classes,
      "benign_label": self.config.benign_label,
      "benign_label_index": self.benign_label_index,
      "hyperparameters": {
        "eps": self.config.eps,
        "min_samples": self.config.min_samples,
        "metric": self.config.metric,
        "algorithm": self.config.algorithm,
        "leaf_size": self.config.leaf_size,
        "max_clustering_samples": self.config.max_clustering_samples,
      },
      "visualization_paths": visualization_paths,
      "trained_at": datetime.now(timezone.utc).isoformat(),
    }

    metadata_path = output_path / self.config.metadata_filename
    with open(metadata_path, "w", encoding="utf-8") as metadata_file:
      json.dump(metadata_payload, metadata_file, indent=2)

    cluster_count = int(evaluation_results["metrics"]["cluster_count"])
    noise_count = int(evaluation_results["metrics"]["noise_count"])

    self.report = DBSCANTrainingReport(
      model_name="dbscan",
      algorithm="DBSCAN",
      dataset="CICIDS2017",
      train_samples=int(len(X_train)),
      test_samples=int(len(X_test)),
      feature_count=int(X_train.shape[1]),
      cluster_count=cluster_count,
      noise_count=noise_count,
      metrics=evaluation_results["metrics"],
      cluster_distribution=evaluation_results["train_cluster_distribution"],
      visualization_paths=visualization_paths,
      model_path=str(model_path),
      metrics_path=str(metrics_path),
      metadata_path=str(metadata_path),
      train_labels_path=str(train_labels_path),
      test_labels_path=str(test_labels_path),
      trained_at=datetime.now(timezone.utc).isoformat(),
    )

    logger.info("Saved evaluation metrics to %s", metrics_path)
    logger.info("Saved model metadata to %s", metadata_path)
    logger.info("Saved cluster labels to %s and %s", train_labels_path, test_labels_path)
    return self.report

  def run(self) -> DBSCANTrainingReport:
    X_train, X_test, y_train, y_test = self.load_training_data()
    train_labels, test_labels = self.cluster(X_train, X_test)
    evaluation_results = self.evaluate(
      X_train=X_train,
      y_train=y_train,
      train_labels=train_labels,
      test_labels=test_labels,
      y_test=y_test,
    )
    visualization_paths = self.visualize(
      X_train=X_train,
      X_test=X_test,
      y_train=y_train,
      y_test=y_test,
      train_labels=train_labels,
      test_labels=test_labels,
    )
    report = self.save_results(
      evaluation_results=evaluation_results,
      visualization_paths=visualization_paths,
      X_train=X_train,
      X_test=X_test,
      train_labels=train_labels,
      test_labels=test_labels,
    )

    logger.info("DBSCAN clustering pipeline completed")
    logger.info("Clusters: %s", report.cluster_count)
    logger.info("Noise points: %s", report.noise_count)
    logger.info("Adjusted Rand Index: %.4f", report.metrics["adjusted_rand_index"])
    logger.info("Normalized Mutual Info: %.4f", report.metrics["normalized_mutual_info"])

    return report


def run_dbscan_training(
  features_path: Optional[str] = None,
  processed_data_path: Optional[str] = None,
  model_output_path: Optional[str] = None,
  eps: float = 0.8,
  min_samples: int = 5,
  max_clustering_samples: Optional[int] = 25000,
  random_state: int = 42,
) -> DBSCANTrainingReport:
  config = DBSCANTrainingConfig()

  if features_path:
    config.features_path = Path(features_path)

  if processed_data_path:
    config.processed_data_path = Path(processed_data_path)

  if model_output_path:
    config.model_output_path = Path(model_output_path)

  config.eps = eps
  config.min_samples = min_samples
  config.max_clustering_samples = max_clustering_samples
  config.random_state = random_state

  trainer = DBSCANTrainer(config=config)
  return trainer.run()


if __name__ == "__main__":
  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
  )
  run_dbscan_training()
