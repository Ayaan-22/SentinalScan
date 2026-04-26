from fastapi.testclient import TestClient
from app.main import app
import pytest

client = TestClient(app)

# ─── Health Check ──────────────────────────────────────────────────────
def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "2.0.0"

# ─── Auth Tests ────────────────────────────────────────────────────────
def test_scan_without_api_key_returns_401():
    """Requests without X-API-Key header should be rejected."""
    response = client.post("/api/v1/scan/", json={"target_url": "https://example.com"})
    assert response.status_code == 401

def test_scan_with_wrong_api_key_returns_403():
    """Requests with an incorrect API key should be forbidden."""
    headers = {"X-API-Key": "wrong_key_here"}
    response = client.post(
        "/api/v1/scan/", 
        json={"target_url": "https://example.com"}, 
        headers=headers
    )
    assert response.status_code == 403

def test_scan_with_valid_api_key():
    """Requests with the correct API key should succeed."""
    headers = {"X-API-Key": "dev_api_key_12345"}
    response = client.post(
        "/api/v1/scan/", 
        json={"target_url": "https://example.com"}, 
        headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == "pending"

# ─── Scan Lifecycle ────────────────────────────────────────────────────
def test_scan_lifecycle():
    """Full lifecycle: start → status → results → logs."""
    headers = {"X-API-Key": "dev_api_key_12345"}
    
    # Start
    start_resp = client.post(
        "/api/v1/scan/", 
        json={"target_url": "https://example.com"}, 
        headers=headers
    )
    assert start_resp.status_code == 200
    scan_id = start_resp.json()["scan_id"]
    
    # Status
    status_resp = client.get(f"/api/v1/scan/{scan_id}", headers=headers)
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] in ["pending", "running", "completed"]
    
    # Results
    results_resp = client.get(f"/api/v1/scan/{scan_id}/results", headers=headers)
    assert results_resp.status_code == 200
    assert isinstance(results_resp.json(), list)
    
    # Logs
    logs_resp = client.get(f"/api/v1/scan/{scan_id}/logs", headers=headers)
    assert logs_resp.status_code == 200
    assert isinstance(logs_resp.json(), list)

def test_scan_not_found():
    """Non-existent scan ID should return 404."""
    headers = {"X-API-Key": "dev_api_key_12345"}
    response = client.get("/api/v1/scan/nonexistent-id-123", headers=headers)
    assert response.status_code == 404

# ─── URL Validation ────────────────────────────────────────────────────
def test_scan_rejects_invalid_url():
    """URLs not starting with http(s) should be rejected."""
    headers = {"X-API-Key": "dev_api_key_12345"}
    response = client.post(
        "/api/v1/scan/", 
        json={"target_url": "ftp://example.com"}, 
        headers=headers
    )
    assert response.status_code == 422  # Pydantic validation error

def test_scan_rejects_no_url():
    """Missing target_url should be rejected."""
    headers = {"X-API-Key": "dev_api_key_12345"}
    response = client.post("/api/v1/scan/", json={}, headers=headers)
    assert response.status_code == 422
