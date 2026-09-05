"""
CNN inference for encrypted-traffic-style flow tensors.

Loads a trained Keras CNN and maps tabular flow features to the
verified production input path: 78 features → pad to 81 → 9x9x1 → 15 classes.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

import numpy as np
from tensorflow import keras

from ml.features.feature_extraction import (
  CNN_DEFAULT_GRID_SIZE,
  FeatureExtractionConfig,
  FeatureExtractor,
)

logger = logging.getLogger("ai-engine.cnn_inference")

DEFAULT_MODEL_OUTPUT_PATH = Path(__file__).resolve().parents[1] / "models" / "tensorflow"
DEFAULT_MODEL_FILENAME = "cnn_encrypted_traffic_model.keras"
DEFAULT_METADATA_FILENAME = "cnn_metadata.json"


@dataclass
class CNNPredictionResult:
  predicted_label: str
  predicted_class_index: int
  confidence: float
  probabilities: dict[str, float]
  is_encrypted_traffic_simulation: bool = True


class CNNPredictionHelper:
  """Load a trained CNN and run encrypted-traffic-style inference."""

  def __init__(
    self,
    model_path: Union[str, Path],
    metadata_path: Optional[Union[str, Path]] = None,
    label_classes: Optional[list[str]] = None,
    grid_height: int = CNN_DEFAULT_GRID_SIZE,
    grid_width: int = CNN_DEFAULT_GRID_SIZE,
  ) -> None:
    self.model_path = Path(model_path)
    self.metadata_path = Path(metadata_path) if metadata_path else self.model_path.parent / DEFAULT_METADATA_FILENAME
    self.grid_height = grid_height
    self.grid_width = grid_width
    self.label_classes = label_classes or []
    self.input_shape: Optional[tuple[int, ...]] = None

    self.model = keras.models.load_model(self.model_path)
    self._load_metadata()

  def _load_metadata(self) -> None:
    if not self.metadata_path.exists():
      logger.warning("CNN metadata file not found at %s", self.metadata_path)
      return

    with open(self.metadata_path, "r", encoding="utf-8") as metadata_file:
      metadata = json.load(metadata_file)

    if not self.label_classes:
      self.label_classes = metadata.get("label_classes", [])

    input_shape = metadata.get("input_shape")
    if input_shape:
      self.input_shape = tuple(input_shape)

    grid_shape = metadata.get("grid_shape", {})
    self.grid_height = int(grid_shape.get("height", self.grid_height))
    self.grid_width = int(grid_shape.get("width", self.grid_width))

  @classmethod
  def from_artifacts(
    cls,
    model_output_path: Optional[Union[str, Path]] = None,
    model_filename: str = DEFAULT_MODEL_FILENAME,
    metadata_filename: str = DEFAULT_METADATA_FILENAME,
  ) -> "CNNPredictionHelper":
    output_path = Path(model_output_path or DEFAULT_MODEL_OUTPUT_PATH)
    return cls(
      model_path=output_path / model_filename,
      metadata_path=output_path / metadata_filename,
    )

  def _reshape_features(self, feature_matrix: np.ndarray) -> np.ndarray:
    if feature_matrix.ndim == 4:
      return feature_matrix

    if feature_matrix.ndim == 1:
      feature_matrix = feature_matrix.reshape(1, -1)

    if feature_matrix.ndim != 2:
      raise ValueError("Expected 2D tabular features or 4D CNN tensors")

    extractor = FeatureExtractor(
      FeatureExtractionConfig(
        cnn_grid_height=self.grid_height,
        cnn_grid_width=self.grid_width,
      )
    )
    return extractor.reshape_for_cnn(
      feature_matrix,
      grid_height=self.grid_height,
      grid_width=self.grid_width,
    )

  def _decode_prediction(self, probabilities: np.ndarray) -> CNNPredictionResult:
    if probabilities.ndim == 2:
      probabilities = probabilities[0]

    predicted_class_index = int(np.argmax(probabilities))
    confidence = float(probabilities[predicted_class_index])

    if self.label_classes and predicted_class_index < len(self.label_classes):
      predicted_label = self.label_classes[predicted_class_index]
      probability_map = {
        self.label_classes[index]: float(probabilities[index])
        for index in range(min(len(self.label_classes), len(probabilities)))
      }
    else:
      predicted_label = str(predicted_class_index)
      probability_map = {str(index): float(value) for index, value in enumerate(probabilities)}

    return CNNPredictionResult(
      predicted_label=predicted_label,
      predicted_class_index=predicted_class_index,
      confidence=confidence,
      probabilities=probability_map,
    )

  def predict_proba(self, features: np.ndarray) -> np.ndarray:
    tensor_input = self._reshape_features(features)
    return self.model.predict(tensor_input, verbose=0)

  def predict(self, features: np.ndarray) -> list[CNNPredictionResult]:
    probabilities = self.predict_proba(features)

    if probabilities.ndim == 1:
      return [self._decode_prediction(probabilities)]

    return [self._decode_prediction(probabilities[index]) for index in range(len(probabilities))]

  def predict_single(self, features: np.ndarray) -> CNNPredictionResult:
    results = self.predict(features)
    return results[0]
