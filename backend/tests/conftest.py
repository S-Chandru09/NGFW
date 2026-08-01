from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client() -> TestClient:
  with (
    patch("database.connect_to_mongodb", new_callable=AsyncMock),
    patch("database.close_mongodb_connection", new_callable=AsyncMock),
    patch("database.ping_database", new_callable=AsyncMock, return_value=True),
    patch("main.connect_to_mongodb", new_callable=AsyncMock),
    patch("main.close_mongodb_connection", new_callable=AsyncMock),
    patch("main.ping_database", new_callable=AsyncMock, return_value=True),
  ):
    from main import app

    with TestClient(app) as test_client:
      yield test_client
