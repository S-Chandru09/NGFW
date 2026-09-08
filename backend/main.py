import logging
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
#my project own modules
from api.router import api_router
from api.routes.websocket_alerts import router as websocket_router
from config import settings
from database import close_mongodb_connection, connect_to_mongodb, mongodb_manager, ping_database

logging.basicConfig(
  level=getattr(logging, settings.log_level.upper(), logging.INFO),
  format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
  stream=sys.stdout,
)
logger = logging.getLogger("ai-ngfw")


@asynccontextmanager
async def lifespan(app: FastAPI):
  logger.info(
    "Starting %s v%s [%s]",
    settings.app_name,
    settings.app_version,
    settings.environment,
  )

  try:
    await connect_to_mongodb()
  except Exception as exc:
    logger.error("Failed to connect to MongoDB: %s", exc)
    if settings.is_production:
      raise

  yield

  await close_mongodb_connection()
  logger.info("Application shutdown complete")


app = FastAPI(
  title=settings.app_name,
  description=settings.app_description,
  version=settings.app_version,
  debug=settings.debug,
  docs_url="/docs" if not settings.is_production else "/docs",
  redoc_url="/redoc" if not settings.is_production else "/redoc",
  openapi_url="/openapi.json",
  lifespan=lifespan,
)

app.add_middleware(
  CORSMiddleware,
  allow_origins=settings.cors_origins,
  allow_credentials=settings.cors_allow_credentials,
  allow_methods=settings.cors_allow_methods,
  allow_headers=settings.cors_allow_headers,
)

app.include_router(api_router, prefix=settings.api_v1_prefix)
app.include_router(websocket_router)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
  errors = []
  for error in exc.errors():
    errors.append(
      {
        "field": ".".join(str(location) for location in error.get("loc", [])),
        "message": error.get("msg"),
        "type": error.get("type"),
      }
    )

  return JSONResponse(
    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
    content={
      "success": False,
      "message": "Request validation failed",
      "errors": errors,
    },
  )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
  logger.exception("Unhandled exception on %s %s", request.method, request.url.path)

  return JSONResponse(
    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    content={
      "success": False,
      "message": "Internal server error",
      "detail": str(exc) if settings.debug else "An unexpected error occurred",
    },
  )


@app.get("/", tags=["Health"])
async def root():
  return {
    "success": True,
    "message": "AI-Powered Next Generation Firewall API is running",
    "application": settings.app_name,
    "version": settings.app_version,
    "environment": settings.environment,
    "docs": "/docs",
    "health": "/health",
  }


@app.get("/health", tags=["Health"])
async def health_check():
  database_status = "disconnected"
  database_error = None

  if mongodb_manager.client is not None and mongodb_manager.database is not None:
    try:
      is_alive = await ping_database()
      database_status = "connected" if is_alive else "error"
      if not is_alive:
        database_error = "MongoDB ping failed"
    except Exception as exc:
      database_status = "error"
      database_error = str(exc)

  overall_status = "healthy" if database_status == "connected" else "degraded"

  response = {
    "success": overall_status == "healthy",
    "status": overall_status,
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "application": settings.app_name,
    "version": settings.app_version,
    "environment": settings.environment,
    "services": {
      "api": "running",
      "mongodb": {
        "status": database_status,
        "database": settings.mongodb_database,
      },
      "zero_trust": {
        "enabled": settings.zero_trust_enabled,
      },
      "network_capture": {
        "enabled": settings.network_capture_enabled,
      },
    },
  }

  if database_error:
    response["services"]["mongodb"]["error"] = database_error

  return response


@app.get("/health/ready", tags=["Health"])
async def readiness_check():
  if mongodb_manager.client is None or mongodb_manager.database is None:
    return JSONResponse(
      status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
      content={
        "success": False,
        "status": "not_ready",
        "message": "MongoDB is not connected",
      },
    )

  try:
    is_alive = await ping_database()
    if not is_alive:
      raise RuntimeError("MongoDB ping failed")
  except Exception as exc:
    return JSONResponse(
      status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
      content={
        "success": False,
        "status": "not_ready",
        "message": "MongoDB ping failed",
        "detail": str(exc),
      },
    )

  return {
    "success": True,
    "status": "ready",
    "message": "All required services are available",
  }


@app.get("/health/live", tags=["Health"])
async def liveness_check():
  return {
    "success": True,
    "status": "alive",
    "message": "Application process is running",
  }


if __name__ == "__main__":
  import uvicorn

  uvicorn.run(
    "main:app",
    host=settings.host,
    port=settings.port,
    reload=settings.reload and settings.is_development,
    log_level=settings.log_level.lower(),
  )
