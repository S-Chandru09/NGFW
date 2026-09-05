"""
Train CNN model for encrypted traffic simulation on CICIDS2017.

Flow statistics are reshaped into 9x9x1 tensors to simulate encrypted
payload fingerprints without decryption. Supports training, evaluation,
model persistence, and inference via a prediction helper.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

import joblib
import numpy as np
from sklearn.metrics import (
  accuracy_score,
  classification_report,
  confusion_matrix,
  f1_score,
  precision_score,
  recall_score,
)
from tensorflow import keras

from ml.features.feature_extraction import (
  CNN_DEFAULT_GRID_SIZE,
  DEFAULT_FEATURES_OUTPUT_PATH,
  FeatureExtractionConfig,
  FeatureExtractor,
)
from ml.inference.cnn_inference import (
  CNNPredictionHelper,
  CNNPredictionResult,
  DEFAULT_METADATA_FILENAME,
  DEFAULT_MODEL_FILENAME,
  DEFAULT_MODEL_OUTPUT_PATH,
)

logger = logging.getLogger("ai-engine.train_cnn")

DEFAULT_PROCESSED_DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "processed" / "cicids2017"
DEFAULT_METRICS_FILENAME = "cnn_metrics.json"


@dataclass
class CNNTrainingConfig:
  features_path: Path = DEFAULT_FEATURES_OUTPUT_PATH
  processed_data_path: Path = DEFAULT_PROCESSED_DATA_PATH
  model_output_path: Path = DEFAULT_MODEL_OUTPUT_PATH
  model_filename: str = DEFAULT_MODEL_FILENAME
  metrics_filename: str = DEFAULT_METRICS_FILENAME
  metadata_filename: str = DEFAULT_METADATA_FILENAME
  grid_height: int = CNN_DEFAULT_GRID_SIZE
  grid_width: int = CNN_DEFAULT_GRID_SIZE
  epochs: int = 25
  batch_size: int = 128
  learning_rate: float = 0.001
  validation_split: float = 0.1
  early_stopping_patience: int = 5
  random_state: int = 42
  use_class_weights: bool = True
  max_training_samples: Optional[int] = 150000
  max_test_samples: Optional[int] = 30000


@dataclass
class CNNTrainingReport:
  model_name: str
  algorithm: str
  dataset: str
  task: str
  train_samples: int
  test_samples: int
  input_shape: list[int]
  class_count: int
  metrics: dict
  confusion_matrix: list[list[int]]
  classification_report: dict
  training_history: dict
  model_path: str
  metrics_path: str
  metadata_path: str
  trained_at: str


class CNNTrainer:
  def __init__(self, config: Optional[CNNTrainingConfig] = None) -> None:
    self.config = config or CNNTrainingConfig()
    self.model: Optional[keras.Model] = None
    self.feature_names: list[str] = []
    self.label_classes: list[str] = []
    self.input_shape: tuple[int, ...] = (
      self.config.grid_height,
      self.config.grid_width,
      1,
    )
    self.training_history: Optional[keras.callbacks.History] = None
    self.report: Optional[CNNTrainingReport] = None

  def load_training_data(self) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    logger.info("Loading CNN feature set for encrypted traffic simulation")

    processed_path = Path(self.config.processed_data_path)
    cnn_feature_path = Path(self.config.features_path) / "cnn"
    metadata_file = cnn_feature_path / "metadata.json"

    y_train = np.load(processed_path / "y_train.npy")
    y_test = np.load(processed_path / "y_test.npy")
    self._load_label_classes()

    train_indices = self._get_sample_indices(len(y_train), self.config.max_training_samples)
    test_indices = self._get_sample_indices(len(y_test), self.config.max_test_samples)
    y_train = y_train[train_indices]
    y_test = y_test[test_indices]

    if metadata_file.exists():
      with open(metadata_file, "r", encoding="utf-8") as file:
        metadata = json.load(file)
      self.feature_names = metadata.get("feature_names", [])
      model_metadata = metadata.get("metadata", {})
      self.input_shape = tuple(model_metadata.get("input_shape", self.input_shape))
      self.config.grid_height = int(model_metadata.get("grid_height", self.config.grid_height))
      self.config.grid_width = int(model_metadata.get("grid_width", self.config.grid_width))

    if (cnn_feature_path / "X_train.npy").exists():
      logger.info("Loading CNN tensors with memory mapping and subsampling")
      X_train_mmap = np.load(cnn_feature_path / "X_train.npy", mmap_mode="r")
      X_test_mmap = np.load(cnn_feature_path / "X_test.npy", mmap_mode="r")
      X_train = np.asarray(X_train_mmap[train_indices], dtype=np.float32)
      X_test = np.asarray(X_test_mmap[test_indices], dtype=np.float32)
      self.input_shape = tuple(X_train.shape[1:])
    else:
      logger.warning("CNN feature set not found. Building tensors from processed dataset.")
      raw_X_train = np.load(processed_path / "X_train.npy", mmap_mode="r")
      raw_X_test = np.load(processed_path / "X_test.npy", mmap_mode="r")

      metadata_path = processed_path / "metadata.json"
      if metadata_path.exists():
        with open(metadata_path, "r", encoding="utf-8") as file:
          metadata = json.load(file)
        self.feature_names = metadata.get("feature_columns", [])
        self.label_classes = metadata.get("label_classes", self.label_classes)

      extractor = FeatureExtractor(
        FeatureExtractionConfig(
          processed_data_path=self.config.processed_data_path,
          cnn_grid_height=self.config.grid_height,
          cnn_grid_width=self.config.grid_width,
        )
      )
      X_train = extractor.reshape_for_cnn(np.asarray(raw_X_train[train_indices], dtype=np.float32))
      X_test = extractor.reshape_for_cnn(np.asarray(raw_X_test[test_indices], dtype=np.float32))
      self.input_shape = tuple(X_train.shape[1:])

    logger.info(
      "Training data loaded | train=%s | test=%s | input_shape=%s",
      len(X_train),
      len(X_test),
      self.input_shape,
    )
    return X_train, X_test, y_train, y_test

  def _get_sample_indices(self, sample_count: int, max_samples: Optional[int]) -> np.ndarray:
    if max_samples is None or sample_count <= max_samples:
      return np.arange(sample_count)

    rng = np.random.default_rng(self.config.random_state)
    selected_indices = rng.choice(sample_count, size=max_samples, replace=False)
    logger.info(
      "Subsampled CNN data | original=%s | used=%s",
      sample_count,
      max_samples,
    )
    return np.sort(selected_indices)

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

  def _compute_class_weights(self, y_train: np.ndarray) -> dict[int, float]:
    class_values, class_counts = np.unique(y_train, return_counts=True)
    total_samples = len(y_train)
    class_weights = {
      int(class_value): float(total_samples / (len(class_values) * count))
      for class_value, count in zip(class_values, class_counts)
    }
    return class_weights

  def build_model(self, num_classes: int) -> keras.Model:
    model = keras.Sequential(
      [
        keras.layers.Input(shape=self.input_shape, name="encrypted_traffic_input"),
        keras.layers.Conv2D(32, (3, 3), activation="relu", padding="same"),
        keras.layers.BatchNormalization(),
        keras.layers.MaxPooling2D((2, 2)),
        keras.layers.Conv2D(64, (3, 3), activation="relu", padding="same"),
        keras.layers.BatchNormalization(),
        keras.layers.MaxPooling2D((2, 2)),
        keras.layers.Conv2D(128, (3, 3), activation="relu", padding="same"),
        keras.layers.BatchNormalization(),
        keras.layers.GlobalAveragePooling2D(),
        keras.layers.Dropout(0.4),
        keras.layers.Dense(128, activation="relu"),
        keras.layers.Dropout(0.3),
        keras.layers.Dense(num_classes, activation="softmax", name="threat_class_output"),
      ],
      name="encrypted_traffic_cnn",
    )

    model.compile(
      optimizer=keras.optimizers.Adam(learning_rate=self.config.learning_rate),
      loss="sparse_categorical_crossentropy",
      metrics=["accuracy"],
    )
    return model

  def train(self, X_train: np.ndarray, y_train: np.ndarray) -> keras.Model:
    logger.info("Training CNN for encrypted traffic simulation")

    num_classes = int(len(np.unique(y_train)))
    self.model = self.build_model(num_classes=num_classes)

    callbacks = [
      keras.callbacks.EarlyStopping(
        monitor="val_loss",
        patience=self.config.early_stopping_patience,
        restore_best_weights=True,
      ),
      keras.callbacks.ReduceLROnPlateau(
        monitor="val_loss",
        factor=0.5,
        patience=2,
        min_lr=1e-6,
      ),
    ]

    fit_kwargs: dict = {
      "x": X_train,
      "y": y_train,
      "epochs": self.config.epochs,
      "batch_size": self.config.batch_size,
      "validation_split": self.config.validation_split,
      "callbacks": callbacks,
      "verbose": 1,
    }

    if self.config.use_class_weights:
      fit_kwargs["class_weight"] = self._compute_class_weights(y_train)

    self.training_history = self.model.fit(**fit_kwargs)
    logger.info("CNN training completed")
    return self.model

  def _get_target_names(self, y_test: np.ndarray) -> list[str]:
    if self.label_classes:
      return self.label_classes

    unique_labels = sorted(np.unique(y_test).tolist())
    return [str(label) for label in unique_labels]

  def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> dict:
    if self.model is None:
      raise ValueError("Model has not been trained yet")

    logger.info("Evaluating CNN model")
    probabilities = self.model.predict(X_test, verbose=0)
    y_pred = np.argmax(probabilities, axis=1)
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
      "y_pred": y_pred.tolist(),
      "probabilities": probabilities.tolist(),
    }

  def _serialize_training_history(self) -> dict:
    if self.training_history is None:
      return {}

    serialized_history: dict[str, list[float]] = {}
    for metric_name, values in self.training_history.history.items():
      serialized_history[metric_name] = [float(value) for value in values]
    return serialized_history

  def save_model(self) -> Path:
    if self.model is None:
      raise ValueError("Model has not been trained yet")

    output_path = Path(self.config.model_output_path)
    output_path.mkdir(parents=True, exist_ok=True)

    model_path = output_path / self.config.model_filename
    self.model.save(model_path)
    logger.info("Saved CNN model to %s", model_path)
    return model_path

  def save_training_artifacts(
    self,
    evaluation_results: dict,
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
  ) -> CNNTrainingReport:
    model_path = self.save_model()

    output_path = Path(self.config.model_output_path)
    output_path.mkdir(parents=True, exist_ok=True)

    training_history = self._serialize_training_history()
    class_count = int(len(np.unique(y_train)))

    metrics_payload = {
      "model_name": "cnn_encrypted_traffic",
      "algorithm": "Convolutional Neural Network",
      "dataset": "CICIDS2017",
      "task": "encrypted_traffic_simulation",
      "metrics": evaluation_results["metrics"],
      "confusion_matrix": evaluation_results["confusion_matrix"],
      "classification_report": evaluation_results["classification_report"],
      "training_history": training_history,
      "train_samples": int(len(X_train)),
      "test_samples": int(len(X_test)),
      "input_shape": list(self.input_shape),
      "class_count": class_count,
      "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }

    metrics_path = output_path / self.config.metrics_filename
    with open(metrics_path, "w", encoding="utf-8") as metrics_file:
      json.dump(metrics_payload, metrics_file, indent=2)

    metadata_payload = {
      "model_name": "cnn_encrypted_traffic",
      "algorithm": "Convolutional Neural Network",
      "dataset": "CICIDS2017",
      "task": "encrypted_traffic_simulation",
      "description": (
        "CNN trained on reshaped flow tensors that simulate encrypted traffic "
        "fingerprints without payload decryption."
      ),
      "model_path": str(model_path),
      "prediction_helper": "CNNPredictionHelper",
      "feature_names": self.feature_names,
      "label_classes": self.label_classes,
      "input_shape": list(self.input_shape),
      "grid_shape": {
        "height": self.config.grid_height,
        "width": self.config.grid_width,
        "channels": 1,
      },
      "hyperparameters": {
        "epochs": self.config.epochs,
        "batch_size": self.config.batch_size,
        "learning_rate": self.config.learning_rate,
        "validation_split": self.config.validation_split,
        "early_stopping_patience": self.config.early_stopping_patience,
        "use_class_weights": self.config.use_class_weights,
        "random_state": self.config.random_state,
      },
      "trained_at": datetime.now(timezone.utc).isoformat(),
    }

    metadata_path = output_path / self.config.metadata_filename
    with open(metadata_path, "w", encoding="utf-8") as metadata_file:
      json.dump(metadata_payload, metadata_file, indent=2)

    self.report = CNNTrainingReport(
      model_name="cnn_encrypted_traffic",
      algorithm="Convolutional Neural Network",
      dataset="CICIDS2017",
      task="encrypted_traffic_simulation",
      train_samples=int(len(X_train)),
      test_samples=int(len(X_test)),
      input_shape=list(self.input_shape),
      class_count=class_count,
      metrics=evaluation_results["metrics"],
      confusion_matrix=evaluation_results["confusion_matrix"],
      classification_report=evaluation_results["classification_report"],
      training_history=training_history,
      model_path=str(model_path),
      metrics_path=str(metrics_path),
      metadata_path=str(metadata_path),
      trained_at=datetime.now(timezone.utc).isoformat(),
    )

    logger.info("Saved evaluation metrics to %s", metrics_path)
    logger.info("Saved model metadata to %s", metadata_path)
    return self.report

  def run(self) -> CNNTrainingReport:
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

    logger.info("CNN training pipeline completed")
    logger.info("Accuracy: %.4f", report.metrics["accuracy"])
    logger.info("F1 Macro: %.4f", report.metrics["f1_macro"])
    logger.info("F1 Weighted: %.4f", report.metrics["f1_weighted"])

    return report


def run_cnn_training(
  features_path: Optional[str] = None,
  processed_data_path: Optional[str] = None,
  model_output_path: Optional[str] = None,
  epochs: int = 25,
  batch_size: int = 128,
  learning_rate: float = 0.001,
  random_state: int = 42,
) -> CNNTrainingReport:
  config = CNNTrainingConfig()

  if features_path:
    config.features_path = Path(features_path)

  if processed_data_path:
    config.processed_data_path = Path(processed_data_path)

  if model_output_path:
    config.model_output_path = Path(model_output_path)

  config.epochs = epochs
  config.batch_size = batch_size
  config.learning_rate = learning_rate
  config.random_state = random_state

  trainer = CNNTrainer(config=config)
  return trainer.run()


if __name__ == "__main__":
  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
  )
  run_cnn_training()
