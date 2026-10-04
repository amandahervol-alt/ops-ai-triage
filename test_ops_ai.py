"""
Pytest Test Suite for OpsAI-Triage
Verifies API endpoints, Pydantic schema validation, and deterministic guardrails.
"""

import pytest
from fastapi.testclient import TestClient
from main import app
from schemas import SeverityLevel

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "mode": "active"}


def test_triage_log_endpoint_success():
    sample_log = {
        "log_content": "ERROR 2026-10-03 18:00:00 [payment-service] DatabaseTimeoutException: Connection attempt to postgresql://db.internal:5432 timed out after 30000ms. API_KEY=secret_12345",
        "service_name": "payment-service",
        "environment": "production"
    }

    response = client.post("/api/v1/triage-log", json=sample_log)
    assert response.status_code == 200
    
    data = response.json()
    assert data["service_name"] == "payment-service"
    assert "DatabaseTimeout" in data["error_type"]
    assert data["security_risk_detected"] is True
    assert data["severity"] == SeverityLevel.HIGH.value
    assert "def test_service_timeout_handling" in data["generated_pytest_fix"]


def test_audit_pr_endpoint_security_risk():
    sample_diff = {
        "git_diff": "diff --git a/app.py b/app.py\n+ secret_token = 'sk_live_999999'\n+ eval(user_input)",
        "repository": "billing-backend",
        "author": "dev-user"
    }

    response = client.post("/api/v1/audit-pr", json=sample_diff)
    assert response.status_code == 200

    data = response.json()
    assert data["repository"] == "billing-backend"
    assert data["approval_recommendation"] == "BLOCK_SECURITY_RISK"
    assert len(data["security_vulnerabilities"]) > 0
    assert data["hallucination_guardrail_passed"] is True


def test_invalid_payload_fails_pydantic_validation():
    # Payload missing required min_length log_content
    invalid_log = {"log_content": "short"}
    response = client.post("/api/v1/triage-log", json=invalid_log)
    assert response.status_code == 422  # Unprocessable Entity
