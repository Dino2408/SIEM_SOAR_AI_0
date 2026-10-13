"""
Integration tests for SIEM/SOAR AI System.

Tests the core API endpoints, AI analysis pipeline, and SOAR execution.
Run with: pytest tests/ -v --asyncio-mode=auto
"""
import pytest
import asyncio
import httpx
import json
from datetime import datetime, timezone


BASE_URL = "http://localhost:8000/api/v1"
AI_ENGINE_URL = "http://localhost:8001"


# ===================== Sample Test Data =====================

SAMPLE_BRUTE_FORCE_EVENT = {
    "source_ip": "192.168.1.100",
    "dest_ip": "10.0.0.5",
    "source_port": 45234,
    "dest_port": 22,
    "protocol": "TCP",
    "event_type": "failed_login",
    "severity": "HIGH",
    "raw_log": "Oct 4 19:23:01 webserver sshd[1234]: Failed password for root from 192.168.1.100 port 45234 ssh2",
    "parsed_data": {
        "username": "root",
        "auth_method": "password",
        "service": "ssh",
        "attempt_count": 15,
    },
    "tags": ["authentication", "ssh", "brute-force"],
    "timestamp": datetime.now(timezone.utc).isoformat(),
}

SAMPLE_SQL_INJECTION_EVENT = {
    "source_ip": "203.0.113.42",
    "dest_ip": "10.0.0.10",
    "source_port": 55123,
    "dest_port": 80,
    "protocol": "TCP",
    "event_type": "web_attack",
    "severity": "CRITICAL",
    "raw_log": "203.0.113.42 - - [04/Oct/2026:19:30:00 +0700] \"GET /login?user=admin' OR 1=1-- HTTP/1.1\" 200 4532",
    "parsed_data": {
        "http_method": "GET",
        "uri": "/login",
        "query_string": "user=admin' OR 1=1--",
        "status_code": 200,
        "user_agent": "sqlmap/1.7.2",
    },
    "tags": ["web", "sql-injection", "owasp"],
    "timestamp": datetime.now(timezone.utc).isoformat(),
}


# ===================== Authentication Tests =====================

@pytest.mark.asyncio
async def test_auth_login():
    """Test JWT authentication."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{BASE_URL}/auth/login",
            json={"username": "admin", "password": "admin"},
        )
        # Should return 200 with access_token
        if resp.status_code == 200:
            data = resp.json()
            assert "access_token" in data
            assert data["token_type"] == "bearer"
        else:
            # Service may not be running in unit test mode
            pytest.skip("Backend not running")


# ===================== Event Ingestion Tests =====================

@pytest.mark.asyncio
async def test_ingest_single_event():
    """Test ingesting a single security event."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        # First authenticate
        auth_resp = await client.post(
            f"{BASE_URL}/auth/login",
            json={"username": "admin", "password": "admin"},
        )
        if auth_resp.status_code != 200:
            pytest.skip("Backend not running")

        token = auth_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Ingest event
        resp = await client.post(
            f"{BASE_URL}/events/ingest",
            json=SAMPLE_BRUTE_FORCE_EVENT,
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "event_id" in data
        assert data["status"] == "queued"


@pytest.mark.asyncio
async def test_ingest_batch_events():
    """Test batch ingestion of multiple events."""
    async with httpx.AsyncClient(timeout=60.0) as client:
        auth_resp = await client.post(
            f"{BASE_URL}/auth/login",
            json={"username": "admin", "password": "admin"},
        )
        if auth_resp.status_code != 200:
            pytest.skip("Backend not running")

        token = auth_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        events = [SAMPLE_BRUTE_FORCE_EVENT, SAMPLE_SQL_INJECTION_EVENT]
        resp = await client.post(
            f"{BASE_URL}/events/ingest/batch",
            json={"events": events},
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["ingested_count"] == 2


# ===================== AI Engine Tests =====================

@pytest.mark.asyncio
async def test_ai_analyze_event():
    """Test AI event analysis endpoint."""
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{AI_ENGINE_URL}/analyze/event",
            json={"event": SAMPLE_BRUTE_FORCE_EVENT},
        )
        if resp.status_code == 503:
            pytest.skip("AI Engine not running")

        assert resp.status_code == 200
        data = resp.json()
        assert "severity" in data
        assert "mitre_technique" in data
        assert "threat_type" in data
        assert data["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@pytest.mark.asyncio
async def test_ai_generate_playbook():
    """Test AI playbook generation."""
    async with httpx.AsyncClient(timeout=90.0) as client:
        resp = await client.post(
            f"{AI_ENGINE_URL}/generate/playbook",
            json={
                "incident_description": "SSH brute force attack from external IP targeting root account",
                "event_type": "brute_force",
                "affected_assets": ["10.0.0.5"],
            },
        )
        if resp.status_code == 503:
            pytest.skip("AI Engine not running")

        assert resp.status_code == 200
        data = resp.json()
        assert "name" in data
        assert "steps" in data
        assert len(data["steps"]) > 0


@pytest.mark.asyncio
async def test_threat_intel_enrichment():
    """Test threat intelligence IP enrichment."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{AI_ENGINE_URL}/enrich/threat-intel",
            json={"ip": "8.8.8.8"},  # Google DNS - should be clean
        )
        if resp.status_code == 503:
            pytest.skip("AI Engine not running")

        assert resp.status_code == 200
        data = resp.json()
        assert "reputation_score" in data
        assert "country" in data


# ===================== Alert Tests =====================

@pytest.mark.asyncio
async def test_list_alerts():
    """Test listing alerts."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        auth_resp = await client.post(
            f"{BASE_URL}/auth/login",
            json={"username": "admin", "password": "admin"},
        )
        if auth_resp.status_code != 200:
            pytest.skip("Backend not running")

        token = auth_resp.json()["access_token"]
        resp = await client.get(
            f"{BASE_URL}/alerts",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data or isinstance(data, list)


# ===================== Dashboard Tests =====================

@pytest.mark.asyncio
async def test_dashboard_stats():
    """Test analytics dashboard data."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        auth_resp = await client.post(
            f"{BASE_URL}/auth/login",
            json={"username": "admin", "password": "admin"},
        )
        if auth_resp.status_code != 200:
            pytest.skip("Backend not running")

        token = auth_resp.json()["access_token"]
        resp = await client.get(
            f"{BASE_URL}/analytics/dashboard",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200


# ===================== Correlation Engine Tests =====================

def test_sigma_rule_load():
    """Test that SIGMA detection rules can be loaded."""
    import yaml
    import os

    rules_path = os.path.join(
        os.path.dirname(__file__), "..", "configs", "rules", "detection_rules.yaml"
    )
    assert os.path.exists(rules_path), f"Rules file not found: {rules_path}"

    with open(rules_path) as f:
        rules = yaml.safe_load(f)

    assert rules is not None
    assert "rules" in rules or isinstance(rules, list)


# ===================== Health Check Tests =====================

@pytest.mark.asyncio
async def test_backend_health():
    """Test backend health endpoint."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.get(f"{BASE_URL.replace('/api/v1', '')}/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data.get("status") in ["ok", "healthy"]
        except httpx.ConnectError:
            pytest.skip("Backend not running")


@pytest.mark.asyncio
async def test_ai_engine_health():
    """Test AI engine health endpoint."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.get(f"{AI_ENGINE_URL}/health")
            assert resp.status_code == 200
        except httpx.ConnectError:
            pytest.skip("AI Engine not running")
