"""
CICIDS2017 dataset preprocessing pipeline.

Handles missing values, categorical encoding, feature scaling,
train/test splitting, and saving processed datasets for ML training.
"""

from __future__ import annotations

import gc
import json
import logging
import warnings
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

warnings.filterwarnings("ignore", category=FutureWarning)

logging.basicConfig(
  level=logging.INFO,
  format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("ai-engine.preprocessing")

DEFAULT_LABEL_COLUMN = "Label"
DEFAULT_RAW_DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "raw" / "cicids2017"
DEFAULT_PROCESSED_DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "processed" / "cicids2017"


@dataclass
class PreprocessingConfig:
  raw_data_path: Path = DEFAULT_RAW_DATA_PATH
  processed_data_path: Path = DEFAULT_PROCESSED_DATA_PATH
  label_column: str = DEFAULT_LABEL_COLUMN
  test_size: float = 0.2
  random_state: int = 42
  drop_duplicates: bool = True
  remove_infinite_values: bool = True
  fill_missing_strategy: str = "median"
  min_label_samples: int = 10
  save_csv: bool = False
  save_numpy: bool = True
  save_artifacts: bool = True


@dataclass
class PreprocessingReport:
  total_rows_loaded: int
  total_rows_after_cleaning: int
  duplicate_rows_removed: int
  missing_values_before: int
  missing_values_after: int
  infinite_values_replaced: int
  feature_count: int
  class_count: int
  train_samples: int
  test_samples: int
  label_distribution: dict[str, int]
  processed_at: str


class CICIDS2017Preprocessor:
  def __init__(self, config: Optional[PreprocessingConfig] = None) -> None:
    self.config = config or PreprocessingConfig()
    self.scaler = StandardScaler()
    self.label_encoder = LabelEncoder()
    self.feature_columns: list[str] = []
    self.report: Optional[PreprocessingReport] = None

  def _find_csv_files(self) -> list[Path]:
    raw_path = Path(self.config.raw_data_path)

    if not raw_path.exists():
      raise FileNotFoundError(
        f"CICIDS2017 raw data path not found: {raw_path}. "
        "Place CICIDS2017 CSV files in this directory."
      )

    csv_files = sorted(raw_path.glob("*.csv"))

    if not csv_files:
      csv_files = sorted(raw_path.rglob("*.csv"))

    if not csv_files:
      raise FileNotFoundError(f"No CSV files found in {raw_path}")

    logger.info("Found %s CICIDS2017 CSV files", len(csv_files))
    return csv_files

  @staticmethod
  def _normalize_column_names(columns: pd.Index) -> pd.Index:
    return (
      columns.str.strip()
      .str.replace(" ", "_")
      .str.replace("/", "_")
      .str.replace("(", "", regex=False)
      .str.replace(")", "", regex=False)
      .str.replace("__", "_", regex=False)
    )

  def _downcast_numeric_columns(self, dataframe: pd.DataFrame) -> pd.DataFrame:
    float_columns = dataframe.select_dtypes(include=["float64"]).columns
    if len(float_columns) > 0:
      dataframe[float_columns] = dataframe[float_columns].astype(np.float32)

    integer_columns = [
      column
      for column in dataframe.select_dtypes(include=["int64"]).columns
      if column != self.config.label_column
    ]
    if integer_columns:
      dataframe[integer_columns] = dataframe[integer_columns].apply(
        pd.to_numeric,
        downcast="integer",
      )

    return dataframe

  def load_dataset(self) -> pd.DataFrame:
    csv_files = self._find_csv_files()
    dataframes: list[pd.DataFrame] = []

    for csv_file in csv_files:
      logger.info("Loading file: %s", csv_file.name)
      dataframe = pd.read_csv(csv_file, low_memory=False)
      dataframe.columns = self._normalize_column_names(dataframe.columns)
      dataframe = self._downcast_numeric_columns(dataframe)
      dataframes.append(dataframe)

    combined_dataframe = pd.concat(dataframes, ignore_index=True)
    dataframes.clear()
    gc.collect()
    logger.info("Loaded %s total rows from CICIDS2017", len(combined_dataframe))
    return combined_dataframe

  def _clean_column_names(self, dataframe: pd.DataFrame) -> pd.DataFrame:
    dataframe.columns = self._normalize_column_names(dataframe.columns)
    return dataframe

  def _handle_missing_values(self, dataframe: pd.DataFrame) -> tuple[pd.DataFrame, int, int]:
    missing_before = int(dataframe.isna().sum().sum())

    dataframe.replace([np.inf, -np.inf], np.nan, inplace=True)

    numeric_columns = dataframe.select_dtypes(include=[np.number]).columns.tolist()
    non_numeric_columns = [column for column in dataframe.columns if column not in numeric_columns]

    for column in numeric_columns:
      if dataframe[column].isna().any():
        if self.config.fill_missing_strategy == "median":
          fill_value = dataframe[column].median()
        elif self.config.fill_missing_strategy == "mean":
          fill_value = dataframe[column].mean()
        else:
          fill_value = 0

        if pd.isna(fill_value):
          fill_value = 0

        dataframe[column] = dataframe[column].fillna(fill_value)

    for column in non_numeric_columns:
      if dataframe[column].isna().any():
        mode_values = dataframe[column].mode(dropna=True)
        fill_value = mode_values.iloc[0] if not mode_values.empty else "unknown"
        dataframe[column] = dataframe[column].fillna(fill_value)

    missing_after = int(dataframe.isna().sum().sum())
    return dataframe, missing_before, missing_after

  def _replace_infinite_values(self, dataframe: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    numeric_dataframe = dataframe.select_dtypes(include=[np.number])
    infinite_mask = np.isinf(numeric_dataframe.to_numpy())
    infinite_count = int(infinite_mask.sum())

    if infinite_count == 0:
      return dataframe, 0

    dataframe.replace([np.inf, -np.inf], np.nan, inplace=True)

    for column in dataframe.select_dtypes(include=[np.number]).columns:
      if dataframe[column].isna().any():
        fill_value = dataframe[column].median()
        if pd.isna(fill_value):
          fill_value = 0
        dataframe[column] = dataframe[column].fillna(fill_value)

    return dataframe, infinite_count

  def _encode_labels(self, labels: pd.Series) -> np.ndarray:
    normalized_labels = labels.astype(str).str.strip()
    encoded_labels = self.label_encoder.fit_transform(normalized_labels)
    logger.info("Encoded %s unique labels", len(self.label_encoder.classes_))
    return encoded_labels

  def _encode_features(self, features: pd.DataFrame) -> pd.DataFrame:
    encoded_features = features.copy()

    categorical_columns = encoded_features.select_dtypes(include=["object", "category"]).columns.tolist()

    for column in categorical_columns:
      encoded_features[column] = LabelEncoder().fit_transform(
        encoded_features[column].astype(str).str.strip()
      )

    return encoded_features

  def _remove_rare_labels(self, features: pd.DataFrame, labels: pd.Series) -> tuple[pd.DataFrame, pd.Series]:
    label_counts = labels.value_counts()
    valid_labels = label_counts[label_counts >= self.config.min_label_samples].index
    mask = labels.isin(valid_labels)

    filtered_features = features.loc[mask].reset_index(drop=True)
    filtered_labels = labels.loc[mask].reset_index(drop=True)

    removed_count = len(labels) - len(filtered_labels)
    if removed_count > 0:
      logger.info("Removed %s rows with rare labels", removed_count)

    return filtered_features, filtered_labels

  def _scale_features(
    self,
    train_features: np.ndarray,
    test_features: np.ndarray,
    batch_size: int = 100_000,
  ) -> tuple[np.ndarray, np.ndarray]:
    train_array = np.ascontiguousarray(train_features, dtype=np.float32)
    test_array = np.ascontiguousarray(test_features, dtype=np.float32)

    for start in range(0, train_array.shape[0], batch_size):
      self.scaler.partial_fit(train_array[start : start + batch_size])

    scaled_train = np.empty(train_array.shape, dtype=np.float32)
    for start in range(0, train_array.shape[0], batch_size):
      end = min(start + batch_size, train_array.shape[0])
      scaled_train[start:end] = self.scaler.transform(train_array[start:end]).astype(
        np.float32,
        copy=False,
      )

    scaled_test = np.empty(test_array.shape, dtype=np.float32)
    for start in range(0, test_array.shape[0], batch_size):
      end = min(start + batch_size, test_array.shape[0])
      scaled_test[start:end] = self.scaler.transform(test_array[start:end]).astype(
        np.float32,
        copy=False,
      )

    return scaled_train, scaled_test

  def _prepare_features_and_labels(self, dataframe: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    if self.config.label_column not in dataframe.columns:
      raise ValueError(
        f"Label column '{self.config.label_column}' not found. "
        f"Available columns: {list(dataframe.columns)}"
      )

    labels = dataframe[self.config.label_column].astype(str).str.strip()
    features = dataframe.drop(columns=[self.config.label_column])
    features = features.select_dtypes(include=[np.number, "object", "category"])

    self.feature_columns = features.columns.tolist()
    return features, labels

  def preprocess(self) -> dict[str, object]:
    raw_dataframe = self.load_dataset()
    total_rows_loaded = len(raw_dataframe)

    cleaned_dataframe = self._clean_column_names(raw_dataframe)

    if self.config.remove_infinite_values:
      cleaned_dataframe, infinite_values_replaced = self._replace_infinite_values(cleaned_dataframe)
    else:
      infinite_values_replaced = 0

    cleaned_dataframe, missing_before, missing_after = self._handle_missing_values(cleaned_dataframe)

    duplicate_rows_removed = 0
    if self.config.drop_duplicates:
      before_drop = len(cleaned_dataframe)
      cleaned_dataframe = cleaned_dataframe.drop_duplicates().reset_index(drop=True)
      duplicate_rows_removed = before_drop - len(cleaned_dataframe)

    features, labels = self._prepare_features_and_labels(cleaned_dataframe)
    total_rows_after_cleaning = len(cleaned_dataframe)
    del cleaned_dataframe
    gc.collect()

    features, labels = self._remove_rare_labels(features, labels)

    encoded_features = self._encode_features(features)
    encoded_features = encoded_features.astype(np.float32)
    del features
    gc.collect()
    encoded_labels = self._encode_labels(labels)

    feature_array = encoded_features.to_numpy()
    del encoded_features
    gc.collect()

    train_features, test_features, train_labels, test_labels = train_test_split(
      feature_array,
      encoded_labels,
      test_size=self.config.test_size,
      random_state=self.config.random_state,
      stratify=encoded_labels,
    )
    del feature_array
    del encoded_labels
    gc.collect()

    scaled_train_features, scaled_test_features = self._scale_features(
      train_features,
      test_features,
    )

    self.report = PreprocessingReport(
      total_rows_loaded=total_rows_loaded,
      total_rows_after_cleaning=total_rows_after_cleaning,
      duplicate_rows_removed=duplicate_rows_removed,
      missing_values_before=missing_before,
      missing_values_after=missing_after,
      infinite_values_replaced=infinite_values_replaced,
      feature_count=len(self.feature_columns),
      class_count=len(self.label_encoder.classes_),
      train_samples=len(scaled_train_features),
      test_samples=len(scaled_test_features),
      label_distribution=labels.value_counts().to_dict(),
      processed_at=datetime.now(timezone.utc).isoformat(),
    )

    processed_data = {
      "X_train": scaled_train_features,
      "X_test": scaled_test_features,
      "y_train": train_labels,
      "y_test": test_labels,
      "feature_columns": self.feature_columns,
      "label_classes": self.label_encoder.classes_.tolist(),
      "scaler": self.scaler,
      "label_encoder": self.label_encoder,
      "report": self.report,
    }

    self.save_processed_dataset(processed_data)
    return processed_data

  def save_processed_dataset(self, processed_data: dict[str, object]) -> Path:
    output_path = Path(self.config.processed_data_path)
    output_path.mkdir(parents=True, exist_ok=True)

    if self.config.save_numpy:
      np.save(output_path / "X_train.npy", processed_data["X_train"])
      np.save(output_path / "X_test.npy", processed_data["X_test"])
      np.save(output_path / "y_train.npy", processed_data["y_train"])
      np.save(output_path / "y_test.npy", processed_data["y_test"])
      logger.info("Saved NumPy arrays to %s", output_path)

    if self.config.save_csv:
      train_dataframe = pd.DataFrame(processed_data["X_train"], columns=self.feature_columns)
      train_dataframe["label"] = processed_data["y_train"]
      train_dataframe["split"] = "train"

      test_dataframe = pd.DataFrame(processed_data["X_test"], columns=self.feature_columns)
      test_dataframe["label"] = processed_data["y_test"]
      test_dataframe["split"] = "test"

      combined_dataframe = pd.concat([train_dataframe, test_dataframe], ignore_index=True)
      combined_dataframe.to_csv(output_path / "cicids2017_processed.csv", index=False)
      logger.info("Saved processed CSV to %s", output_path / "cicids2017_processed.csv")

    if self.config.save_artifacts:
      joblib.dump(processed_data["scaler"], output_path / "scaler.pkl")
      joblib.dump(processed_data["label_encoder"], output_path / "label_encoder.pkl")

      metadata = {
        "dataset": "CICIDS2017",
        "feature_columns": self.feature_columns,
        "label_classes": processed_data["label_classes"],
        "test_size": self.config.test_size,
        "random_state": self.config.random_state,
        "fill_missing_strategy": self.config.fill_missing_strategy,
        "report": asdict(processed_data["report"]) if processed_data.get("report") else {},
      }

      with open(output_path / "metadata.json", "w", encoding="utf-8") as metadata_file:
        json.dump(metadata, metadata_file, indent=2)

      logger.info("Saved preprocessing artifacts to %s", output_path)

    return output_path

  @staticmethod
  def load_processed_dataset(processed_data_path: Optional[Path] = None) -> dict[str, object]:
    output_path = Path(processed_data_path or DEFAULT_PROCESSED_DATA_PATH)

    if not output_path.exists():
      raise FileNotFoundError(f"Processed dataset path not found: {output_path}")

    loaded_data = {
      "X_train": np.load(output_path / "X_train.npy"),
      "X_test": np.load(output_path / "X_test.npy"),
      "y_train": np.load(output_path / "y_train.npy"),
      "y_test": np.load(output_path / "y_test.npy"),
      "scaler": joblib.load(output_path / "scaler.pkl"),
      "label_encoder": joblib.load(output_path / "label_encoder.pkl"),
    }

    metadata_file = output_path / "metadata.json"
    if metadata_file.exists():
      with open(metadata_file, "r", encoding="utf-8") as file:
        loaded_data["metadata"] = json.load(file)

    logger.info("Loaded processed CICIDS2017 dataset from %s", output_path)
    return loaded_data


def run_preprocessing(
  raw_data_path: Optional[str] = None,
  processed_data_path: Optional[str] = None,
  test_size: float = 0.2,
  random_state: int = 42,
) -> dict[str, object]:
  config = PreprocessingConfig()

  if raw_data_path:
    config.raw_data_path = Path(raw_data_path)

  if processed_data_path:
    config.processed_data_path = Path(processed_data_path)

  config.test_size = test_size
  config.random_state = random_state

  preprocessor = CICIDS2017Preprocessor(config=config)
  processed_data = preprocessor.preprocess()

  logger.info("CICIDS2017 preprocessing completed successfully")
  logger.info("Train samples: %s", len(processed_data["X_train"]))
  logger.info("Test samples: %s", len(processed_data["X_test"]))
  logger.info("Features: %s", len(processed_data["feature_columns"]))
  logger.info("Classes: %s", len(processed_data["label_classes"]))

  return processed_data


if __name__ == "__main__":
  run_preprocessing()
