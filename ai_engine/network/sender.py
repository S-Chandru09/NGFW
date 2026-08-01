"""
Send extracted network flow features to the backend API.

Handles request retries, validation, timeouts, and HTTP/connection errors.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Union

import httpx
import numpy as np

from network.flow_generator import FlowGenerationReport, NetworkFlow

logger = logging.getLogger("ai-engine.sender")

DEFAULT_BACKEND_URL = "http://localhost:8000"
DEFAULT_FLOWS_ENDPOINT = "/api/v1/network/flows"
DEFAULT_BATCH_FLOWS_ENDPOINT = "/api/v1/network/flows/batch"
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BACKOFF_SECONDS = 1.5


class SenderError(Exception):
  """Base exception for feature sender errors."""


class SenderValidationError(SenderError):
  """Raised when payload validation fails before sending."""


class SenderConnectionError(SenderError):
  """Raised when the backend cannot be reached."""


class SenderTimeoutError(SenderError):
  """Raised when a backend request times out."""


class SenderHTTPError(SenderError):
  """Raised when the backend returns a non-success HTTP status."""

  def __init__(self, message: str, status_code: int, response_body: Optional[str] = None) -> None:
    super().__init__(message)
    self.status_code = status_code
    self.response_body = response_body


@dataclass
class SenderConfig:
  backend_url: str = DEFAULT_BACKEND_URL
  flows_endpoint: str = DEFAULT_FLOWS_ENDPOINT
  batch_flows_endpoint: str = DEFAULT_BATCH_FLOWS_ENDPOINT
  timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
  max_retries: int = DEFAULT_MAX_RETRIES
  retry_backoff_seconds: float = DEFAULT_RETRY_BACKOFF_SECONDS
  api_token: Optional[str] = None
  internal_api_key: Optional[str] = None
  enabled: bool = True

  @classmethod
  def from_env(cls) -> "SenderConfig":
    return cls(
      backend_url=os.getenv("BACKEND_URL", DEFAULT_BACKEND_URL).rstrip("/"),
      flows_endpoint=os.getenv("BACKEND_FLOWS_ENDPOINT", DEFAULT_FLOWS_ENDPOINT),
      batch_flows_endpoint=os.getenv("BACKEND_BATCH_FLOWS_ENDPOINT", DEFAULT_BATCH_FLOWS_ENDPOINT),
      timeout_seconds=int(os.getenv("BACKEND_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)),
      max_retries=int(os.getenv("BACKEND_MAX_RETRIES", DEFAULT_MAX_RETRIES)),
      retry_backoff_seconds=float(os.getenv("BACKEND_RETRY_BACKOFF_SECONDS", DEFAULT_RETRY_BACKOFF_SECONDS)),
      api_token=os.getenv("BACKEND_API_TOKEN"),
      internal_api_key=os.getenv("INTERNAL_API_KEY"),
      enabled=os.getenv("BACKEND_SENDER_ENABLED", "true").lower() == "true",
    )


@dataclass
class SendResult:
  success: bool
  flow_id: Optional[str] = None
  status_code: Optional[int] = None
  message: str = ""
  response: Optional[dict[str, Any]] = None
  error: Optional[str] = None
  attempts: int = 0
  sent_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

  def to_dict(self) -> dict[str, Any]:
    return asdict(self)


@dataclass
class BatchSendResult:
  success: bool
  total_flows: int
  sent_count: int
  failed_count: int
  results: list[SendResult] = field(default_factory=list)
  message: str = ""
  sent_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

  def to_dict(self) -> dict[str, Any]:
    payload = asdict(self)
    payload["results"] = [result.to_dict() for result in self.results]
    return payload


class FeatureSender:
  """Send extracted flow features to the backend API."""

  def __init__(self, config: Optional[SenderConfig] = None) -> None:
    self.config = config or SenderConfig.from_env()

  def _build_headers(self) -> dict[str, str]:
    headers = {
      "Content-Type": "application/json",
      "Accept": "application/json",
      "User-Agent": "AI-NGFW-FeatureSender/1.0",
    }

    if self.config.api_token:
      headers["Authorization"] = f"Bearer {self.config.api_token}"

    if self.config.internal_api_key:
      headers["X-Internal-Api-Key"] = self.config.internal_api_key

    return headers

  def _serialize_value(self, value: Any) -> Any:
    if isinstance(value, (np.integer,)):
      return int(value)

    if isinstance(value, (np.floating,)):
      return float(value)

    if isinstance(value, np.ndarray):
      return value.tolist()

    if isinstance(value, datetime):
      return value.isoformat()

    return value

  def _serialize_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
    serialized: dict[str, Any] = {}

    for key, value in payload.items():
      if isinstance(value, dict):
        serialized[key] = self._serialize_payload(value)
      elif isinstance(value, list):
        serialized[key] = [self._serialize_value(item) for item in value]
      else:
        serialized[key] = self._serialize_value(value)

    return serialized

  def _validate_features(self, features: dict[str, Any]) -> None:
    if not features:
      raise SenderValidationError("Feature payload is empty")

    if not isinstance(features, dict):
      raise SenderValidationError("Features must be provided as a dictionary")

  def build_flow_payload(
    self,
    flow: NetworkFlow,
    prediction: Optional[dict[str, Any]] = None,
    extra_metadata: Optional[dict[str, Any]] = None,
  ) -> dict[str, Any]:
    """Build a backend-ready payload from a generated network flow."""
    metadata = {
      "source": "ai_engine",
      "feature_version": "1.0",
      "sent_at": datetime.now(timezone.utc).isoformat(),
    }
    if extra_metadata:
      metadata.update(extra_metadata)

    payload = {
      "flow_id": flow.flow_id,
      "source_ip": flow.src_ip,
      "destination_ip": flow.dst_ip,
      "source_mac": flow.src_mac,
      "destination_mac": flow.dst_mac,
      "source_port": flow.source_port,
      "destination_port": flow.destination_port,
      "protocol": flow.protocol,
      "captured_at": flow.flow_end_time,
      "flow_start_time": flow.flow_start_time,
      "flow_end_time": flow.flow_end_time,
      "flow_duration": flow.flow_duration,
      "flow_packets_s": flow.flow_packets_s,
      "flow_bytes_s": flow.flow_bytes_s,
      "total_packets": flow.total_packets,
      "total_bytes": flow.total_bytes,
      "total_fwd_packets": flow.total_fwd_packets,
      "total_backward_packets": flow.total_backward_packets,
      "total_length_of_fwd_packets": flow.total_length_of_fwd_packets,
      "total_length_of_bwd_packets": flow.total_length_of_bwd_packets,
      "features": flow.features,
      "metadata": metadata,
    }

    if prediction:
      payload["prediction"] = {
        "attack_label": prediction.get("attack_label"),
        "confidence": prediction.get("confidence"),
        "is_attack": prediction.get("is_attack"),
        "threat_level": prediction.get("threat_level"),
      }
      payload["is_threat"] = bool(prediction.get("is_attack", False))
      payload["threat_label"] = prediction.get("attack_label")
      payload["threat_confidence"] = prediction.get("confidence")

    return self._serialize_payload(payload)

  def build_features_payload(
    self,
    flow_id: str,
    features: dict[str, Any],
    metadata: Optional[dict[str, Any]] = None,
    prediction: Optional[dict[str, Any]] = None,
  ) -> dict[str, Any]:
    """Build a backend payload from a raw feature dictionary."""
    self._validate_features(features)

    payload = {
      "flow_id": flow_id,
      "features": features,
      "metadata": metadata or {
        "source": "ai_engine",
        "feature_version": "1.0",
        "sent_at": datetime.now(timezone.utc).isoformat(),
      },
    }

    if prediction:
      payload["prediction"] = prediction
      payload["is_threat"] = bool(prediction.get("is_attack", False))

    return self._serialize_payload(payload)

  def _post_json(self, endpoint: str, payload: dict[str, Any]) -> httpx.Response:
    url = f"{self.config.backend_url}{endpoint}"
    last_error: Optional[Exception] = None

    for attempt in range(1, self.config.max_retries + 1):
      try:
        with httpx.Client(timeout=self.config.timeout_seconds) as client:
          response = client.post(url, headers=self._build_headers(), json=payload)
          response.raise_for_status()
          return response

      except httpx.TimeoutException as exc:
        last_error = SenderTimeoutError(f"Backend request timed out: {exc}")
        logger.warning("Timeout sending features to %s (attempt %s/%s)", url, attempt, self.config.max_retries)

      except httpx.HTTPStatusError as exc:
        last_error = SenderHTTPError(
          message=f"Backend returned HTTP {exc.response.status_code}",
          status_code=exc.response.status_code,
          response_body=exc.response.text,
        )
        logger.error(
          "HTTP error sending features to %s | status=%s | body=%s",
          url,
          exc.response.status_code,
          exc.response.text,
        )
        break

      except httpx.RequestError as exc:
        last_error = SenderConnectionError(f"Could not connect to backend: {exc}")
        logger.warning(
          "Connection error sending features to %s (attempt %s/%s): %s",
          url,
          attempt,
          self.config.max_retries,
          exc,
        )

      except Exception as exc:
        last_error = SenderError(f"Unexpected sender error: {exc}")
        logger.exception("Unexpected error sending features to %s", url)
        break

      if attempt < self.config.max_retries:
        sleep_seconds = self.config.retry_backoff_seconds * attempt
        time.sleep(sleep_seconds)

    if last_error is None:
      raise SenderError("Failed to send features for an unknown reason")

    raise last_error

  def send_flow(
    self,
    flow: NetworkFlow,
    prediction: Optional[dict[str, Any]] = None,
  ) -> SendResult:
    """Send a single network flow and its extracted features to the backend."""
    if not self.config.enabled:
      return SendResult(
        success=True,
        flow_id=flow.flow_id,
        message="Backend sender is disabled",
        attempts=0,
      )

    try:
      payload = self.build_flow_payload(flow=flow, prediction=prediction)
      response = self._post_json(self.config.flows_endpoint, payload)
      response_data = response.json() if response.content else {}

      return SendResult(
        success=True,
        flow_id=flow.flow_id,
        status_code=response.status_code,
        message=response_data.get("message", "Flow features sent successfully"),
        response=response_data,
        attempts=1,
      )

    except SenderHTTPError as exc:
      return SendResult(
        success=False,
        flow_id=flow.flow_id,
        status_code=exc.status_code,
        message=str(exc),
        error=exc.response_body,
        attempts=self.config.max_retries,
      )

    except (SenderTimeoutError, SenderConnectionError, SenderValidationError, SenderError) as exc:
      return SendResult(
        success=False,
        flow_id=flow.flow_id,
        message=str(exc),
        error=str(exc),
        attempts=self.config.max_retries,
      )

  def send_features(
    self,
    flow_id: str,
    features: dict[str, Any],
    metadata: Optional[dict[str, Any]] = None,
    prediction: Optional[dict[str, Any]] = None,
  ) -> SendResult:
    """Send a raw extracted feature dictionary to the backend."""
    if not self.config.enabled:
      return SendResult(
        success=True,
        flow_id=flow_id,
        message="Backend sender is disabled",
        attempts=0,
      )

    try:
      payload = self.build_features_payload(
        flow_id=flow_id,
        features=features,
        metadata=metadata,
        prediction=prediction,
      )
      response = self._post_json(self.config.flows_endpoint, payload)
      response_data = response.json() if response.content else {}

      return SendResult(
        success=True,
        flow_id=flow_id,
        status_code=response.status_code,
        message=response_data.get("message", "Features sent successfully"),
        response=response_data,
        attempts=1,
      )

    except SenderHTTPError as exc:
      return SendResult(
        success=False,
        flow_id=flow_id,
        status_code=exc.status_code,
        message=str(exc),
        error=exc.response_body,
        attempts=self.config.max_retries,
      )

    except (SenderTimeoutError, SenderConnectionError, SenderValidationError, SenderError) as exc:
      return SendResult(
        success=False,
        flow_id=flow_id,
        message=str(exc),
        error=str(exc),
        attempts=self.config.max_retries,
      )

  def send_flows(
    self,
    flows: list[NetworkFlow],
    predictions: Optional[dict[str, dict[str, Any]]] = None,
    use_batch_endpoint: bool = True,
    extra_metadata: Optional[dict[str, Any]] = None,
    batch_metadata: Optional[dict[str, Any]] = None,
    chunk_size: int = 100,
  ) -> BatchSendResult:
    """Send multiple network flows to the backend."""
    if not flows:
      return BatchSendResult(
        success=True,
        total_flows=0,
        sent_count=0,
        failed_count=0,
        message="No flows to send",
      )

    if not self.config.enabled:
      return BatchSendResult(
        success=True,
        total_flows=len(flows),
        sent_count=0,
        failed_count=0,
        message="Backend sender is disabled",
      )

    predictions = predictions or {}

    if use_batch_endpoint:
      batch_result = self._send_flows_batch(
        flows=flows,
        predictions=predictions,
        extra_metadata=extra_metadata,
        batch_metadata=batch_metadata,
        chunk_size=chunk_size,
      )
      if batch_result.success or batch_result.sent_count > 0:
        return batch_result

      logger.warning("Batch send failed. Falling back to individual flow submissions.")

    results: list[SendResult] = []
    for flow in flows:
      prediction = predictions.get(flow.flow_id)
      payload = self.build_flow_payload(
        flow=flow,
        prediction=prediction,
        extra_metadata=extra_metadata,
      )
      try:
        response = self._post_json(self.config.flows_endpoint, payload)
        response_data = response.json() if response.content else {}
        results.append(
          SendResult(
            success=True,
            flow_id=flow.flow_id,
            status_code=response.status_code,
            message=response_data.get("message", "Flow features sent successfully"),
            response=response_data,
            attempts=1,
          )
        )
      except (SenderHTTPError, SenderTimeoutError, SenderConnectionError, SenderError) as exc:
        results.append(
          SendResult(
            success=False,
            flow_id=flow.flow_id,
            message=str(exc),
            error=str(exc),
            attempts=self.config.max_retries,
          )
        )

    sent_count = sum(1 for result in results if result.success)
    failed_count = len(results) - sent_count

    return BatchSendResult(
      success=failed_count == 0,
      total_flows=len(flows),
      sent_count=sent_count,
      failed_count=failed_count,
      results=results,
      message="Batch flow submission completed",
    )

  def _send_flows_batch(
    self,
    flows: list[NetworkFlow],
    predictions: dict[str, dict[str, Any]],
    extra_metadata: Optional[dict[str, Any]] = None,
    batch_metadata: Optional[dict[str, Any]] = None,
    chunk_size: int = 100,
  ) -> BatchSendResult:
    try:
      results: list[SendResult] = []
      sent_count = 0
      failed_count = 0
      last_message = "Batch flow features sent successfully"
      effective_chunk_size = max(chunk_size, 1)

      for chunk_start in range(0, len(flows), effective_chunk_size):
        chunk = flows[chunk_start:chunk_start + effective_chunk_size]
        payload = {
          "flows": [
            self.build_flow_payload(
              flow=flow,
              prediction=predictions.get(flow.flow_id),
              extra_metadata=extra_metadata,
            )
            for flow in chunk
          ],
          "metadata": {
            "source": "ai_engine",
            "batch_size": len(chunk),
            "sent_at": datetime.now(timezone.utc).isoformat(),
            **(batch_metadata or {}),
          },
        }

        response = self._post_json(self.config.batch_flows_endpoint, payload)
        response_data = response.json() if response.content else {}
        last_message = response_data.get("message", last_message)
        sent_count += int(response_data.get("ingested_count", len(chunk)))
        failed_count += max(len(chunk) - int(response_data.get("ingested_count", len(chunk))), 0)

        results.extend(
          SendResult(
            success=True,
            flow_id=flow.flow_id,
            status_code=response.status_code,
            message="Flow included in successful batch submission",
            response=response_data,
            attempts=1,
          )
          for flow in chunk
        )

      return BatchSendResult(
        success=failed_count == 0,
        total_flows=len(flows),
        sent_count=sent_count,
        failed_count=failed_count,
        results=results,
        message=last_message,
      )

    except (SenderHTTPError, SenderTimeoutError, SenderConnectionError, SenderError) as exc:
      error_message = str(exc)
      if isinstance(exc, SenderHTTPError):
        error_message = exc.response_body or str(exc)

      results = [
        SendResult(
          success=False,
          flow_id=flow.flow_id,
          message="Batch submission failed",
          error=error_message,
          attempts=self.config.max_retries,
        )
        for flow in flows
      ]

      return BatchSendResult(
        success=False,
        total_flows=len(flows),
        sent_count=0,
        failed_count=len(flows),
        results=results,
        message="Batch flow submission failed",
      )

  def send_flow_report(
    self,
    report: FlowGenerationReport,
    predictions: Optional[dict[str, dict[str, Any]]] = None,
  ) -> BatchSendResult:
    """Send all flows from a flow generation report to the backend."""
    return self.send_flows(flows=report.flows, predictions=predictions)


def send_features_to_backend(
  flow_id: str,
  features: dict[str, Any],
  backend_url: Optional[str] = None,
  api_token: Optional[str] = None,
  prediction: Optional[dict[str, Any]] = None,
) -> SendResult:
  """Convenience helper to send extracted features to the backend."""
  config = SenderConfig.from_env()

  if backend_url:
    config.backend_url = backend_url.rstrip("/")

  if api_token:
    config.api_token = api_token

  sender = FeatureSender(config=config)
  return sender.send_features(
    flow_id=flow_id,
    features=features,
    prediction=prediction,
  )


def send_flow_to_backend(
  flow: NetworkFlow,
  backend_url: Optional[str] = None,
  api_token: Optional[str] = None,
  prediction: Optional[dict[str, Any]] = None,
) -> SendResult:
  """Convenience helper to send a network flow to the backend."""
  config = SenderConfig.from_env()

  if backend_url:
    config.backend_url = backend_url.rstrip("/")

  if api_token:
    config.api_token = api_token

  sender = FeatureSender(config=config)
  return sender.send_flow(flow=flow, prediction=prediction)


if __name__ == "__main__":
  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
  )

  sample_features = {
    "flow_duration": 125000.0,
    "flow_packets_s": 42.5,
    "flow_bytes_s": 5120.0,
    "destination_port": 443,
    "protocol": "TCP",
  }

  result = send_features_to_backend(
    flow_id="demo-flow-001",
    features=sample_features,
  )
  print(json.dumps(result.to_dict(), indent=2))
