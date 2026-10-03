import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

def test_dashboard_stats():
    res = client.get("/api/security/dashboard-stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_scans" in data
    assert "total_vulnerabilities" in data
    assert "overall_posture" in data

def test_list_vulnerabilities():
    res = client.get("/api/vulnerabilities")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 1

def test_list_scans():
    res = client.get("/api/scans")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 1

def test_list_reports():
    res = client.get("/api/reports")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 1

def test_trigger_pipeline():
    payload = {
        "target_location": "../target_samples/vulnerable_app.py",
        "target_url": "http://127.0.0.1:5000",
        "scan_type": "sast_only",
        "generate_patches": True
    }
    res = client.post("/api/security/scan", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "scan_id" in data
    assert "security_score" in data
    assert data["total_vulnerabilities"] > 0
