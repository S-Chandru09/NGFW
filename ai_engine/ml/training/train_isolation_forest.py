"""
Train Isolation Forest model for CICIDS2017 anomaly detection.

Loads extracted features, trains the model, evaluates anomaly detection
performance, and saves the trained model and metrics.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
  accuracy_score,
  confusion_matrix,
  f1_score,
  precision_score,
  recall_score,
  roc_auc_score,
)

from ml.features.feature_extraction import DEFAULT_FEATURES_OUTPUT_PATH, FeatureExtractor

logger = logging.getLogger("ai-engine.train_isolation_forest")

DEFAULT_MODEL_OUTPUT_PATH = Path(__file__).resolve().parents[1] / "models" / "sklearn"
DEFAULT_PROCESSED_DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "processed" / "cicids2017"
DEFAULT_MODEL_FILENAME = "isolation_forest_model.pkl"
DEFAULT_METRICS_FILENAME = "isolation_forest_metrics.json"
DEFAULT_METADATA_FILENAME = "isolation_forest_metadata.json"
DEFAULT_BENIGN_LABEL = "BENIGN"


@dataclass
class IsolationForestTrainingConfig:
  features_path: Path = DEFAULT_FEATURES_OUTPUT_PATH
  processed_data_path: Path = DEFAULT_PROCESSED_DATA_PATH
  model_output_path: Path = DEFAULT_MODEL_OUTPUT_PATH
  model_filename: str = DEFAULT_MODEL_FILENAME
  metrics_filename: str = DEFAULT_METRICS_FILENAME
  metadata_filename: str = DEFAULT_METADATA_FILENAME
  n_estimators: int = 200
  max_samples: str | int = "auto"
  contamination: float = 0.1
  max_features: float = 1.0
  bootstrap: bool = False
  random_state: int = 42
  n_jobs: int = -1
  benign_label: str = DEFAULT_BENIGN_LABEL
  train_on_benign_only: bool = True


@dataclass
class IsolationForestTrainingReport:
  model_name: str
  algorithm: str
  dataset: str
  train_samples: int
  test_samples: int
  feature_count: int
  metrics: dict
  confusion_matrix: list[list[int]]
  anomaly_score_summary: dict
  model_path: str
  metrics_path: str
  metadata_path: str
  trained_at: str


class IsolationForestTrainer:
  def __init__(self, config: Optional[IsolationForestTrainingConfig] = None) -> None:
    self.config = config or IsolationForestTrainingConfig()
    self.model: Optional[IsolationForest] = None
    self.feature_names: list[str] = []
    self.label_classes: list[str] = []
    self.benign_label_index: Optional[int] = None
    self.report: Optional[IsolationForestTrainingReport] = None

  def load_training_data(self) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    logger.info("Loading Isolation Forest feature set")

    try:
      feature_set = FeatureExtractor.load_feature_set(
        model_name="isolation_forest",
        features_output_path=self.config.features_path,
      )
      X_train = feature_set.X_train
      X_test = feature_set.X_test
      y_train = feature_set.y_train
      y_test = feature_set.y_test
      self.feature_names = feature_set.feature_names or []

    except FileNotFoundError:
      logger.warning("Isolation Forest feature set not found. Loading from processed dataset.")
      processed_path = Path(self.config.processed_data_path)

      X_train = np.load(processed_path / "X_train.npy")
      X_test = np.load(processed_path / "X_test.npy")
      y_train = np.load(processed_path / "y_train.npy")
      y_test = np.load(processed_path / "y_test.npy")

      metadata_file = processed_path / "metadata.json"
      if metadata_file.exists():
        with open(metadata_file, "r", encoding="utf-8") as file:
          metadata = json.load(file)
        self.feature_names = metadata.get("feature_columns", [])
        self.label_classes = metadata.get("label_classes", [])

    if y_train is None or y_test is None:
      raise ValueError("Labels are required for Isolation Forest evaluation")

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

    binary_labels = np.where(labels == self.benign_label_index, 0, 1)
    return binary_labels.astype(int)

  def _convert_predictions_to_binary(self, predictions: np.ndarray) -> np.ndarray:
    # Isolation Forest: 1 = inlier (normal), -1 = outlier (anomaly)
    return np.where(predictions == -1, 1, 0).astype(int)

  def build_model(self) -> IsolationForest:
    return IsolationForest(
      n_estimators=self.config.n_estimators,
      max_samples=self.config.max_samples,
      contamination=self.config.contamination,
      max_features=self.config.max_features,
      bootstrap=self.config.bootstrap,
      random_state=self.config.random_state,
      n_jobs=self.config.n_jobs,
    )

  def train(self, X_train: np.ndarray, y_train: np.ndarray) -> IsolationForest:
    logger.info("Training Isolation Forest model")

    if self.config.train_on_benign_only:
      benign_mask = y_train == self.benign_label_index
      training_features = X_train[benign_mask]

      if len(training_features) == 0:
        logger.warning("No benign samples found. Training on full training dataset.")
        training_features = X_train
    else:
      training_features = X_train

    self.model = self.build_model()
    self.model.fit(training_features)

    logger.info(
      "Isolation Forest training completed | training_samples=%s",
      len(training_features),
    )
    return self.model

  def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> dict:
    if self.model is None:
      raise ValueError("Model has not been trained yet")

    logger.info("Evaluating Isolation Forest model")

    predictions = self.model.predict(X_test)
    anomaly_scores = self.model.decision_function(X_test)
    score_samples = self.model.score_samples(X_test)

    y_true_binary = self._convert_labels_to_binary(y_test)
    y_pred_binary = self._convert_predictions_to_binary(predictions)

    accuracy = accuracy_score(y_true_binary, y_pred_binary)
    precision = precision_score(y_true_binary, y_pred_binary, zero_division=0)
    recall = recall_score(y_true_binary, y_pred_binary, zero_division=0)
    f1 = f1_score(y_true_binary, y_pred_binary, zero_division=0)

    try:
      roc_auc = roc_auc_score(y_true_binary, -anomaly_scores)
    except ValueError:
      roc_auc = 0.0

    conf_matrix = confusion_matrix(y_true_binary, y_pred_binary)

    true_anomalies = int(np.sum(y_true_binary == 1))
    predicted_anomalies = int(np.sum(y_pred_binary == 1))
    true_normals = int(np.sum(y_true_binary == 0))
    predicted_normals = int(np.sum(y_pred_binary == 0))

    false_positives = int(np.sum((y_true_binary == 0) & (y_pred_binary == 1)))
    false_negatives = int(np.sum((y_true_binary == 1) & (y_pred_binary == 0)))
    true_positives = int(np.sum((y_true_binary == 1) & (y_pred_binary == 1)))
    true_negatives = int(np.sum((y_true_binary == 0) & (y_pred_binary == 0)))

    false_positive_rate = false_positives / true_normals if true_normals > 0 else 0.0
    false_negative_rate = false_negatives / true_anomalies if true_anomalies > 0 else 0.0
    detection_rate = true_positives / true_anomalies if true_anomalies > 0 else 0.0

    metrics = {
      "accuracy": float(accuracy),
      "precision": float(precision),
      "recall": float(recall),
      "f1_score": float(f1),
      "roc_auc": float(roc_auc),
      "detection_rate": float(detection_rate),
      "false_positive_rate": float(false_positive_rate),
      "false_negative_rate": float(false_negative_rate),
      "true_positives": true_positives,
      "true_negatives": true_negatives,
      "false_positives": false_positives,
      "false_negatives": false_negatives,
      "true_anomalies": true_anomalies,
      "predicted_anomalies": predicted_anomalies,
      "true_normals": true_normals,
      "predicted_normals": predicted_normals,
    }

    anomaly_score_summary = {
      "decision_function_mean": float(np.mean(anomaly_scores)),
      "decision_function_std": float(np.std(anomaly_scores)),
      "decision_function_min": float(np.min(anomaly_scores)),
      "decision_function_max": float(np.max(anomaly_scores)),
      "score_samples_mean": float(np.mean(score_samples)),
      "score_samples_std": float(np.std(score_samples)),
      "score_samples_min": float(np.min(score_samples)),
      "score_samples_max": float(np.max(score_samples)),
    }

    return {
      "metrics": metrics,
      "confusion_matrix": conf_matrix.tolist(),
      "anomaly_score_summary": anomaly_score_summary,
      "predictions": predictions,
      "anomaly_scores": anomaly_scores,
    }

  def save_model(self) -> Path:
    if self.model is None:
      raise ValueError("Model has not been trained yet")

    output_path = Path(self.config.model_output_path)
    output_path.mkdir(parents=True, exist_ok=True)

    model_path = output_path / self.config.model_filename
    joblib.dump(self.model, model_path)
    logger.info("Saved Isolation Forest model to %s", model_path)
    return model_path

  def save_training_artifacts(
    self,
    evaluation_results: dict,
    X_train: np.ndarray,
    X_test: np.ndarray,
  ) -> IsolationForestTrainingReport:
    model_path = self.save_model()

    output_path = Path(self.config.model_output_path)
    output_path.mkdir(parents=True, exist_ok=True)

    metrics_payload = {
      "model_name": "isolation_forest",
      "algorithm": "IsolationForest",
      "dataset": "CICIDS2017",
      "task": "anomaly_detection",
      "metrics": evaluation_results["metrics"],
      "confusion_matrix": evaluation_results["confusion_matrix"],
      "anomaly_score_summary": evaluation_results["anomaly_score_summary"],
      "train_samples": int(len(X_train)),
      "test_samples": int(len(X_test)),
      "feature_count": int(X_train.shape[1]),
      "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }

    metrics_path = output_path / self.config.metrics_filename
    with open(metrics_path, "w", encoding="utf-8") as metrics_file:
      json.dump(metrics_payload, metrics_file, indent=2)

    metadata_payload = {
      "model_name": "isolation_forest",
      "algorithm": "IsolationForest",
      "dataset": "CICIDS2017",
      "task": "anomaly_detection",
      "model_path": str(model_path),
      "feature_names": self.feature_names,
      "label_classes": self.label_classes,
      "benign_label": self.config.benign_label,
      "benign_label_index": self.benign_label_index,
      "hyperparameters": {
        "n_estimators": self.config.n_estimators,
        "max_samples": self.config.max_samples,
        "contamination": self.config.contamination,
        "max_features": self.config.max_features,
        "bootstrap": self.config.bootstrap,
        "random_state": self.config.random_state,
        "train_on_benign_only": self.config.train_on_benign_only,
      },
      "trained_at": datetime.now(timezone.utc).isoformat(),
    }

    metadata_path = output_path / self.config.metadata_filename
    with open(metadata_path, "w", encoding="utf-8") as metadata_file:
      json.dump(metadata_payload, metadata_file, indent=2)

    self.report = IsolationForestTrainingReport(
      model_name="isolation_forest",
      algorithm="IsolationForest",
      dataset="CICIDS2017",
      train_samples=int(len(X_train)),
      test_samples=int(len(X_test)),
      feature_count=int(X_train.shape[1]),
      metrics=evaluation_results["metrics"],
      confusion_matrix=evaluation_results["confusion_matrix"],
      anomaly_score_summary=evaluation_results["anomaly_score_summary"],
      model_path=str(model_path),
      metrics_path=str(metrics_path),
      metadata_path=str(metadata_path),
      trained_at=datetime.now(timezone.utc).isoformat(),
    )

    logger.info("Saved evaluation metrics to %s", metrics_path)
    logger.info("Saved model metadata to %s", metadata_path)
    return self.report

  def run(self) -> IsolationForestTrainingReport:
    X_train, X_test, y_train, y_test = self.load_training_data()
    self.train(X_train, y_train)
    evaluation_results = self.evaluate(X_test, y_test)
    report = self.save_training_artifacts(
      evaluation_results=evaluation_results,
      X_train=X_train,
      X_test=X_test,
    )

    logger.info("Isolation Forest training pipeline completed")
    logger.info("Accuracy: %.4f", report.metrics["accuracy"])
    logger.info("Precision: %.4f", report.metrics["precision"])
    logger.info("Recall: %.4f", report.metrics["recall"])
    logger.info("F1 Score: %.4f", report.metrics["f1_score"])
    logger.info("ROC AUC: %.4f", report.metrics["roc_auc"])

    return report


def run_isolation_forest_training(
  features_path: Optional[str] = None,
  processed_data_path: Optional[str] = None,
  model_output_path: Optional[str] = None,
  n_estimators: int = 200,
  contamination: float = 0.1,
  train_on_benign_only: bool = True,
  random_state: int = 42,
) -> IsolationForestTrainingReport:
  config = IsolationForestTrainingConfig()

  if features_path:
    config.features_path = Path(features_path)

  if processed_data_path:
    config.processed_data_path = Path(processed_data_path)

  if model_output_path:
    config.model_output_path = Path(model_output_path)

  config.n_estimators = n_estimators
  config.contamination = contamination
  config.train_on_benign_only = train_on_benign_only
  config.random_state = random_state

  trainer = IsolationForestTrainer(config=config)
  return trainer.run()


if __name__ == "__main__":
  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
  )
  run_isolation_forest_training()
