def test_root_endpoint(client) -> None:
  response = client.get("/")
  assert response.status_code == 200
  body = response.json()
  assert body["success"] is True
  assert "AI-Powered Next Generation Firewall" in body["message"]


def test_health_endpoint_reports_api_running(client) -> None:
  response = client.get("/health")
  assert response.status_code == 200
  body = response.json()
  assert body["services"]["api"] == "running"
  assert "mongodb" in body["services"]


def test_liveness_endpoint(client) -> None:
  response = client.get("/health/live")
  assert response.status_code == 200
  assert response.json()["status"] == "alive"
