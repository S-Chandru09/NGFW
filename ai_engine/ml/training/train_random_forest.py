"""
Train Random Forest classifier for CICIDS2017 threat detection.

Loads extracted features, trains the model, evaluates performance,
saves the trained model and evaluation metrics.
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
  accuracy_score,
  classification_report,
  confusion_matrix,
  f1_score,
  precision_score,
  recall_score,
)

from ml.features.feature_extraction import DEFAULT_FEATURES_OUTPUT_PATH, FeatureExtractor

logger = logging.getLogger("ai-engine.train_random_forest")

DEFAULT_MODEL_OUTPUT_PATH = Path(__file__).resolve().parents[1] / "models" / "sklearn"
DEFAULT_PROCESSED_DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "processed" / "cicids2017"
DEFAULT_MODEL_FILENAME = "random_forest_model.pkl"
DEFAULT_METRICS_FILENAME = "random_forest_metrics.json"
DEFAULT_METADATA_FILENAME = "random_forest_metadata.json"


@dataclass
class RandomForestTrainingConfig:
  features_path: Path = DEFAULT_FEATURES_OUTPUT_PATH
  processed_data_path: Path = DEFAULT_PROCESSED_DATA_PATH
  model_output_path: Path = DEFAULT_MODEL_OUTPUT_PATH
  model_filename: str = DEFAULT_MODEL_FILENAME
  metrics_filename: str = DEFAULT_METRICS_FILENAME
  metadata_filename: str = DEFAULT_METADATA_FILENAME
  n_estimators: int = 200
  max_depth: Optional[int] = None
  min_samples_split: int = 2
  min_samples_leaf: int = 1
  max_features: str = "sqrt"
  class_weight: str = "balanced"
  random_state: int = 42
  n_jobs: int = -1
  top_feature_importance_count: int = 20


@dataclass
class TrainingReport:
  model_name: str
  algorithm: str
  dataset: str
  train_samples: int
  test_samples: int
  feature_count: int
  class_count: int
  metrics: dict
  confusion_matrix: list[list[int]]
  classification_report: dict
  top_feature_importances: list[dict[str, float]]
  model_path: str
  metrics_path: str
  metadata_path: str
  trained_at: str


class RandomForestTrainer:
  def __init__(self, config: Optional[RandomForestTrainingConfig] = None) -> None:
    self.config = config or RandomForestTrainingConfig()
    self.model: Optional[RandomForestClassifier] = None
    self.feature_names: list[str] = []
    self.label_classes: list[str] = []
    self.report: Optional[TrainingReport] = None

  def load_training_data(self) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    logger.info("Loading Random Forest feature set")

    try:
      feature_set = FeatureExtractor.load_feature_set(
        model_name="random_forest",
        features_output_path=self.config.features_path,
      )
      X_train = feature_set.X_train
      X_test = feature_set.X_test
      y_train = feature_set.y_train
      y_test = feature_set.y_test
      self.feature_names = feature_set.feature_names or []

    except FileNotFoundError:
      logger.warning("Random Forest feature set not found. Loading from processed dataset.")
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
      raise ValueError("Training labels not found for Random Forest model")

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
      return

    label_encoder_path = Path(self.config.processed_data_path) / "label_encoder.pkl"
    if label_encoder_path.exists():
      label_encoder = joblib.load(label_encoder_path)
      self.label_classes = label_encoder.classes_.tolist()
      return

    metadata_file = Path(self.config.processed_data_path) / "metadata.json"
    if metadata_file.exists():
      with open(metadata_file, "r", encoding="utf-8") as file:
        metadata = json.load(file)
      self.label_classes = metadata.get("label_classes", [])

  def build_model(self) -> RandomForestClassifier:
    return RandomForestClassifier(
      n_estimators=self.config.n_estimators,
      max_depth=self.config.max_depth,
      min_samples_split=self.config.min_samples_split,
      min_samples_leaf=self.config.min_samples_leaf,
      max_features=self.config.max_features,
      class_weight=self.config.class_weight,
      random_state=self.config.random_state,
      n_jobs=self.config.n_jobs,
    )

  def train(self, X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    logger.info("Training Random Forest classifier")
    self.model = self.build_model()
    self.model.fit(X_train, y_train)
    logger.info("Random Forest training completed")
    return self.model

  def _get_target_names(self, y_test: np.ndarray) -> list[str]:
    if self.label_classes:
      return self.label_classes

    unique_labels = sorted(np.unique(y_test).tolist())
    return [str(label) for label in unique_labels]

  def evaluate(
    self,
    X_test: np.ndarray,
    y_test: np.ndarray,
  ) -> dict:
    if self.model is None:
      raise ValueError("Model has not been trained yet")

    logger.info("Evaluating Random Forest model")
    y_pred = self.model.predict(X_test)
    target_names = self._get_target_names(y_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision_macro = precision_score(y_test, y_pred, average="macro", zero_division=0)
    recall_macro = recall_score(y_test, y_pred, average="macro", zero_division=0)
    f1_macro = f1_score(y_test, y_pred, average="macro", zero_division=0)
    precision_weighted = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    recall_weighted = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1_weighted = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    conf_matrix = confusion_matrix(y_test, y_pred)
    class_report = classification_report(
      y_test,
      y_pred,
      target_names=target_names if len(target_names) == len(np.unique(y_test)) else None,
      output_dict=True,
      zero_division=0,
    )

    metrics = {
      "accuracy": float(accuracy),
      "precision_macro": float(precision_macro),
      "recall_macro": float(recall_macro),
      "f1_macro": float(f1_macro),
      "precision_weighted": float(precision_weighted),
      "recall_weighted": float(recall_weighted),
      "f1_weighted": float(f1_weighted),
    }

    return {
      "metrics": metrics,
      "confusion_matrix": conf_matrix.tolist(),
      "classification_report": class_report,
      "y_pred": y_pred,
    }

  def _extract_top_feature_importances(self) -> list[dict[str, float]]:
    if self.model is None:
      return []

    importances = self.model.feature_importances_
    feature_names = self.feature_names or [f"feature_{index}" for index in range(len(importances))]

    importance_pairs = [
      {"feature": feature_names[index], "importance": float(importances[index])}
      for index in range(len(importances))
    ]
    importance_pairs.sort(key=lambda item: item["importance"], reverse=True)

    return importance_pairs[: self.config.top_feature_importance_count]

  def save_model(self) -> Path:
    if self.model is None:
      raise ValueError("Model has not been trained yet")

    output_path = Path(self.config.model_output_path)
    output_path.mkdir(parents=True, exist_ok=True)

    model_path = output_path / self.config.model_filename
    joblib.dump(self.model, model_path)
    logger.info("Saved Random Forest model to %s", model_path)
    return model_path

  def save_training_artifacts(
    self,
    evaluation_results: dict,
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
  ) -> TrainingReport:
    model_path = self.save_model()

    output_path = Path(self.config.model_output_path)
    output_path.mkdir(parents=True, exist_ok=True)

    metrics_payload = {
      "model_name": "random_forest",
      "algorithm": "RandomForestClassifier",
      "dataset": "CICIDS2017",
      "metrics": evaluation_results["metrics"],
      "confusion_matrix": evaluation_results["confusion_matrix"],
      "classification_report": evaluation_results["classification_report"],
      "train_samples": int(len(X_train)),
      "test_samples": int(len(X_test)),
      "feature_count": int(X_train.shape[1]),
      "class_count": int(len(np.unique(y_train))),
      "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }

    metrics_path = output_path / self.config.metrics_filename
    with open(metrics_path, "w", encoding="utf-8") as metrics_file:
      json.dump(metrics_payload, metrics_file, indent=2)

    top_feature_importances = self._extract_top_feature_importances()
    metadata_payload = {
      "model_name": "random_forest",
      "algorithm": "RandomForestClassifier",
      "dataset": "CICIDS2017",
      "model_path": str(model_path),
      "feature_names": self.feature_names,
      "label_classes": self.label_classes,
      "hyperparameters": {
        "n_estimators": self.config.n_estimators,
        "max_depth": self.config.max_depth,
        "min_samples_split": self.config.min_samples_split,
        "min_samples_leaf": self.config.min_samples_leaf,
        "max_features": self.config.max_features,
        "class_weight": self.config.class_weight,
        "random_state": self.config.random_state,
      },
      "top_feature_importances": top_feature_importances,
      "trained_at": datetime.now(timezone.utc).isoformat(),
    }

    metadata_path = output_path / self.config.metadata_filename
    with open(metadata_path, "w", encoding="utf-8") as metadata_file:
      json.dump(metadata_payload, metadata_file, indent=2)

    self.report = TrainingReport(
      model_name="random_forest",
      algorithm="RandomForestClassifier",
      dataset="CICIDS2017",
      train_samples=int(len(X_train)),
      test_samples=int(len(X_test)),
      feature_count=int(X_train.shape[1]),
      class_count=int(len(np.unique(y_train))),
      metrics=evaluation_results["metrics"],
      confusion_matrix=evaluation_results["confusion_matrix"],
      classification_report=evaluation_results["classification_report"],
      top_feature_importances=top_feature_importances,
      model_path=str(model_path),
      metrics_path=str(metrics_path),
      metadata_path=str(metadata_path),
      trained_at=datetime.now(timezone.utc).isoformat(),
    )

    logger.info("Saved evaluation metrics to %s", metrics_path)
    logger.info("Saved model metadata to %s", metadata_path)
    return self.report

  def run(self) -> TrainingReport:
    X_train, X_test, y_train, y_test = self.load_training_data()
    self.train(X_train, y_train)
    evaluation_results = self.evaluate(X_test, y_test)
    report = self.save_training_artifacts(
      evaluation_results=evaluation_results,
      X_train=X_train,
      X_test=X_test,
      y_train=y_train,
      y_test=y_test,
    )

    logger.info("Random Forest training pipeline completed")
    logger.info("Accuracy: %.4f", report.metrics["accuracy"])
    logger.info("F1 Macro: %.4f", report.metrics["f1_macro"])
    logger.info("F1 Weighted: %.4f", report.metrics["f1_weighted"])

    return report


def run_random_forest_training(
  features_path: Optional[str] = None,
  processed_data_path: Optional[str] = None,
  model_output_path: Optional[str] = None,
  n_estimators: int = 200,
  max_depth: Optional[int] = None,
  random_state: int = 42,
) -> TrainingReport:
  config = RandomForestTrainingConfig()

  if features_path:
    config.features_path = Path(features_path)

  if processed_data_path:
    config.processed_data_path = Path(processed_data_path)

  if model_output_path:
    config.model_output_path = Path(model_output_path)

  config.n_estimators = n_estimators
  config.max_depth = max_depth
  config.random_state = random_state

  trainer = RandomForestTrainer(config=config)
  return trainer.run()


if __name__ == "__main__":
  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
  )
  run_random_forest_training()
