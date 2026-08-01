import logging
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

import httpx

from config import settings

logger = logging.getLogger("ai-ngfw.ai_engine")


class AIEngineClient:
  def __init__(self) -> None:
    self.base_url = settings.ai_engine_url.rstrip("/")
    self.timeout = settings.ai_engine_timeout_seconds
    self.enabled = settings.ai_engine_enabled

  async def submit_pcap_for_analysis(
    self,
    upload_id: str,
    file_path: str,
    original_filename: str,
    file_hash: str,
    packet_count: int,
    uploaded_by: Optional[str] = None,
  ) -> dict[str, Any]:
    if not self.enabled:
      logger.info("AI Engine is disabled. Skipping PCAP analysis for upload_id=%s", upload_id)
      return {
        "success": True,
        "status": "skipped",
        "message": "AI Engine is disabled",
        "job_id": None,
        "response": None,
      }

    endpoint = f"{self.base_url}{settings.ai_engine_analyze_endpoint}"
    payload = {
      "upload_id": upload_id,
      "file_path": file_path,
      "original_filename": original_filename,
      "file_hash": file_hash,
      "packet_count": packet_count,
      "uploaded_by": uploaded_by,
    }

    try:
      async with httpx.AsyncClient(timeout=self.timeout) as client:
        file_path_obj = Path(file_path)

        if file_path_obj.exists():
          with open(file_path_obj, "rb") as pcap_file:
            files = {
              "file": (original_filename, pcap_file, "application/vnd.tcpdump.pcap"),
            }
            data = {
              "upload_id": upload_id,
              "file_hash": file_hash,
              "packet_count": str(packet_count),
            }

            if uploaded_by:
              data["uploaded_by"] = uploaded_by

            response = await client.post(endpoint, data=data, files=files)
        else:
          response = await client.post(endpoint, json=payload)

        response.raise_for_status()
        response_data = response.json()

        return {
          "success": True,
          "status": response_data.get("status", "queued"),
          "message": response_data.get("message", "PCAP submitted to AI Engine successfully"),
          "job_id": response_data.get("job_id") or response_data.get("analysis_id") or str(uuid4()),
          "response": response_data,
        }

    except httpx.TimeoutException as exc:
      logger.error("AI Engine timeout for upload_id=%s: %s", upload_id, exc)
      return {
        "success": False,
        "status": "failed",
        "message": "AI Engine request timed out",
        "job_id": None,
        "response": None,
        "error": str(exc),
      }

    except httpx.HTTPStatusError as exc:
      logger.error(
        "AI Engine HTTP error for upload_id=%s: %s %s",
        upload_id,
        exc.response.status_code,
        exc.response.text,
      )
      return {
        "success": False,
        "status": "failed",
        "message": f"AI Engine returned HTTP {exc.response.status_code}",
        "job_id": None,
        "response": None,
        "error": exc.response.text,
      }

    except httpx.RequestError as exc:
      logger.error("AI Engine connection error for upload_id=%s: %s", upload_id, exc)
      return {
        "success": False,
        "status": "failed",
        "message": "Could not connect to AI Engine",
        "job_id": None,
        "response": None,
        "error": str(exc),
      }

    except Exception as exc:
      logger.exception("Unexpected AI Engine error for upload_id=%s", upload_id)
      return {
        "success": False,
        "status": "failed",
        "message": "Unexpected AI Engine error",
        "job_id": None,
        "response": None,
        "error": str(exc),
      }


ai_engine_client = AIEngineClient()
