"""
Tests for PromptGuard VDI lifecycle management (TASK-092).

Covers:
- init_session / get_session_id / get_session_start_time
- request_shutdown / is_shutdown_requested
- reset_session
- session_info
- /ready, /live, /session/reset endpoints
- Shutdown middleware rejecting requests during drain
"""
from __future__ import annotations
import json
import pytest
from unittest.mock import patch

from promptguard.config import load_config
from promptguard.lifecycle import (
    init_session,
    get_session_id,
    get_session_start_time,
    is_shutdown_requested,
    request_shutdown,
    reset_session,
    session_info,
    _SHUTDOWN_REQUESTED,
)


# ── Unit tests ─────────────────────────────────────────────────────────────────

class TestSessionInit:
    def test_init_returns_config(self):
        config = init_session()
        assert config is not None
        assert config.version == 1

    def test_init_sets_session_id_from_env(self, monkeypatch):
        monkeypatch.setenv("PROMPTGUARD_SESSION_ID", "vdi-user-42")
        init_session()
        assert get_session_id() == "vdi-user-42"

    def test_init_generates_session_id_if_no_env(self, monkeypatch):
        monkeypatch.delenv("PROMPTGUARD_SESSION_ID", raising=False)
        init_session()
        sid = get_session_id()
        assert sid is not None
        assert sid.startswith("pg-")

    def test_start_time_set(self):
        init_session()
        assert get_session_start_time() > 0


class TestShutdownLifecycle:
    def test_initial_state_not_shutdown(self):
        init_session()
        assert is_shutdown_requested() is False

    def test_request_shutdown_sets_flag(self):
        init_session()
        request_shutdown()
        assert is_shutdown_requested() is True

    def test_reset_clears_shutdown(self):
        init_session()
        request_shutdown()
        assert is_shutdown_requested() is True
        reset_session()
        assert is_shutdown_requested() is False

    def test_reset_clears_session_id(self):
        init_session()
        assert get_session_id() is not None
        reset_session()
        assert get_session_id() is None


class TestSessionInfo:
    def test_session_info_returns_metadata(self):
        init_session()
        info = session_info()
        assert "session_id" in info
        assert "started_at" in info
        assert "uptime_seconds" in info
        assert "shutdown_requested" in info
        assert "state" in info

    def test_session_info_active_state(self):
        init_session()
        info = session_info()
        assert info["state"] == "active"

    def test_session_info_draining_state(self):
        init_session()
        request_shutdown()
        info = session_info()
        assert info["state"] == "draining"


# ── API endpoints ──────────────────────────────────────────────────────────────

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from httpx import AsyncClient, ASGITransport
from promptguard.main import app


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset lifecycle state before each test."""
    reset_session()
    yield
    reset_session()


@pytest.fixture
async def client():
    """Create an async test client with a fresh session and config loaded."""
    from promptguard.main import _config as _peek
    from promptguard import main as main_mod

    # Initialize lifecycle session
    init_session()
    # Ensure global _config is loaded (normally done by lifespan)
    if main_mod._config is None:
        main_mod._config = load_config()
        main_mod._audit = __import__('promptguard.audit.logger', fromlist=['AuditLogger']).AuditLogger(main_mod._config.audit)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    # Cleanup
    main_mod._config = None
    main_mod._audit = None


class TestReadinessEndpoint:
    @pytest.mark.asyncio
    async def test_ready_returns_200(self, client):
        response = await client.get("/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert "session" in data

    @pytest.mark.asyncio
    async def test_ready_returns_503_when_shutdown(self, client):
        request_shutdown()
        response = await client.get("/ready")
        assert response.status_code == 503


class TestLivenessEndpoint:
    @pytest.mark.asyncio
    async def test_live_returns_200(self, client):
        response = await client.get("/live")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "alive"

    @pytest.mark.asyncio
    async def test_live_returns_200_even_when_shutdown(self, client):
        request_shutdown()
        response = await client.get("/live")
        assert response.status_code == 200


class TestSessionResetEndpoint:
    @pytest.mark.asyncio
    async def test_session_reset(self, client):
        response = await client.post("/session/reset")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "reset"
        assert "session" in data


class TestShutdownMiddleware:
    @pytest.mark.asyncio
    async def test_health_allowed_during_shutdown(self, client):
        request_shutdown()
        response = await client.get("/health")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_live_allowed_during_shutdown(self, client):
        request_shutdown()
        response = await client.get("/live")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_hook_rejected_during_shutdown(self, client):
        request_shutdown()
        response = await client.post(
            "/hook/pre-tool",
            json={"tool_name": "Read", "tool_input": "{}"},
        )
        assert response.status_code == 503