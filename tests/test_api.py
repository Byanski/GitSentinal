import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db, clear_auth

@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c

def test_root_serves_html(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "GitSentinel" in response.text

def test_auth_status_unauthenticated(client):
    clear_auth()
    response = client.get("/api/auth/status")
    assert response.status_code == 200
    data = response.json()
    assert data["authenticated"] is False

def test_get_settings(client):
    response = client.get("/api/settings")
    assert response.status_code == 200
    data = response.json()
    assert "settings" in data
    assert "daily_scan_enabled" in data["settings"]

def test_update_settings(client):
    new_settings = {"daily_scan_enabled": "true", "daily_scan_time": "05:15"}
    response = client.post("/api/settings", json={"settings": new_settings})
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["settings"]["daily_scan_time"] == "05:15"

def test_get_findings_and_stats(client):
    resp1 = client.get("/api/findings")
    assert resp1.status_code == 200
    assert "findings" in resp1.json()

    resp2 = client.get("/api/stats")
    assert resp2.status_code == 200
    assert "total_open" in resp2.json()
