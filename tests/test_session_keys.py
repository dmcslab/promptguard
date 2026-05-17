"""
Tests for PromptGuard session key management (TASK-095).

Covers:
- register_session_key / validate_session_key / revoke_session_key
- list_session_keys / prune_expired_keys / clear_all_session_keys
- Key hashing (no plaintext stored)
- Thread safety
- FastAPI /session/key, /session/keys, DELETE /session/key endpoints
- require_api_key accepting session keys
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid

import pytest

from promptguard.session_keys import (
    register_session_key,
    validate_session_key,
    revoke_session_key,
    list_session_keys,
    prune_expired_keys,
    clear_all_session_keys,
    _hash_key,
)
from promptguard.config import AuditConfig


# ── Unit tests ─────────────────────────────────────────────────────────────────

class TestSessionKeyRegistration:
    def setup_method(self):
        clear_all_session_keys()

    def test_register_and_validate(self):
        key = "test-session-key-abc"
        register_session_key(key)
        assert validate_session_key(key) is True

    def test_validate_wrong_key(self):
        register_session_key("correct-key")
        assert validate_session_key("wrong-key") is False

    def test_validate_after_revoke(self):
        key = "revokable-key"
        register_session_key(key)
        assert validate_session_key(key) is True
        revoke_session_key(key)
        assert validate_session_key(key) is False

    def test_revoke_nonexistent_key(self):
        assert revoke_session_key("nonexistent") is False

    def test_register_overwrites(self):
        register_session_key("key-1", source="first")
        register_session_key("key-1", source="second")
        keys = list_session_keys()
        assert len(keys) == 1
        assert keys[0]["source"] == "second"


class TestKeyHashing:
    def test_hash_is_sha256(self):
        key = "test-key"
        expected = hashlib.sha256(key.encode()).hexdigest()
        assert _hash_key(key) == expected

    def test_different_keys_different_hashes(self):
        assert _hash_key("key-a") != _hash_key("key-b")

    def test_no_plaintext_in_store(self):
        clear_all_session_keys()
        register_session_key("secret-key-123")
        keys = list_session_keys()
        assert len(keys) == 1
        # The stored hash should NOT contain the plaintext key
        assert "secret-key-123" not in keys[0]["key_hash"]


class TestKeyListing:
    def setup_method(self):
        clear_all_session_keys()

    def test_list_empty(self):
        assert list_session_keys() == []

    def test_list_includes_metadata(self):
        register_session_key("key-1", source="vdi")
        keys = list_session_keys()
        assert len(keys) == 1
        assert "key_hash" in keys[0]
        assert keys[0]["source"] == "vdi"
        assert "created_at" in keys[0]
        assert "last_used_at" in keys[0]


class TestKeyExpiry:
    def setup_method(self):
        clear_all_session_keys()

    def test_prune_expired_keys(self):
        register_session_key("old-key")
        # Manually age the key
        from promptguard.session_keys import _SESSION_KEYS, _SESSION_LOCK
        with _SESSION_LOCK:
            for h in _SESSION_KEYS:
                _SESSION_KEYS[h]["created_at"] = time.time() - 200_000  # 2+ days old

        pruned = prune_expired_keys(ttl=86_400)  # 1 day TTL
        assert pruned == 1
        assert list_session_keys() == []

    def test_prune_keeps_fresh_keys(self):
        register_session_key("fresh-key")
        pruned = prune_expired_keys(ttl=86_400)
        assert pruned == 0
        assert len(list_session_keys()) == 1


class TestClearAll:
    def setup_method(self):
        clear_all_session_keys()

    def test_clear_all(self):
        register_session_key("key-1")
        register_session_key("key-2")
        count = clear_all_session_keys()
        assert count == 2
        assert list_session_keys() == []


class TestThreadSafety:
    def test_concurrent_register_and_validate(self):
        clear_all_session_keys()
        errors = []

        def register_keys(start, count):
            try:
                for i in range(start, start + count):
                    register_session_key(f"key-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=register_keys, args=(i * 100, 100))
                   for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # All 500 keys should be valid
        for i in range(500):
            assert validate_session_key(f"key-{i}") is True


# ── Integration tests (FastAPI endpoints) ─────────────────────────────────────

import pytest
from fastapi.testclient import TestClient

from promptguard.main import app
from promptguard.config import load_config


@pytest.fixture
def client():
    clear_all_session_keys()
    # Set a known API key for auth
    import os
    os.environ["PROMPTGUARD_API_KEY"] = "test-integration-key"
    from promptguard.main import app
    from promptguard.config import load_config
    from promptguard.main import _config as _orig_config
    # Load config with our API key
    cfg = load_config()
    import promptguard.main as main_mod
    main_mod._config = cfg
    with TestClient(app) as c:
        yield c
    main_mod._config = _orig_config
    os.environ.pop("PROMPTGUARD_API_KEY", None)
    clear_all_session_keys()


class TestSessionKeyEndpoints:
    def test_register_session_key(self, client):
        headers = {"X-PromptGuard-API-Key": "test-integration-key"}
        resp = client.post(
            "/session/key",
            json={"key": "user-session-key-1", "source": "vdi"},
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"
        assert data["source"] == "vdi"

    def test_register_requires_auth(self, client):
        resp = client.post("/session/key", json={"key": "sk-123"})
        assert resp.status_code == 401

    def test_register_requires_key_field(self, client):
        headers = {"X-PromptGuard-API-Key": "test-integration-key"}
        resp = client.post("/session/key", json={}, headers=headers)
        assert resp.status_code == 400

    def test_list_session_keys(self, client):
        headers = {"X-PromptGuard-API-Key": "test-integration-key"}
        # Register a key first
        client.post(
            "/session/key",
            json={"key": "sk-list-test"},
            headers=headers,
        )
        resp = client.get("/session/keys", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "keys" in data
        assert len(data["keys"]) >= 1
        # Should not contain plaintext key
        for k in data["keys"]:
            assert "key_hash" in k
            assert "sk-list-test" not in k["key_hash"]

    def test_revoke_session_key(self, client):
        headers = {"X-PromptGuard-API-Key": "test-integration-key"}
        # Register
        client.post(
            "/session/key",
            json={"key": "sk-revoke-me"},
            headers=headers,
        )
        # Revoke
        resp = client.request(
            "DELETE",
            "/session/key",
            json={"key": "sk-revoke-me"},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"

    def test_revoke_nonexistent_key(self, client):
        headers = {"X-PromptGuard-API-Key": "test-integration-key"}
        resp = client.request(
            "DELETE",
            "/session/key",
            json={"key": "nonexistent-key"},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "not_found"

    def test_session_key_auth(self, client):
        """A registered session key should be accepted by require_api_key."""
        global_headers = {"X-PromptGuard-API-Key": "test-integration-key"}
        # Register a session key
        client.post(
            "/session/key",
            json={"key": "my-session-key"},
            headers=global_headers,
        )
        # Use session key to access a protected endpoint
        session_headers = {"X-PromptGuard-API-Key": "my-session-key"}
        resp = client.get("/audit/stats", headers=session_headers)
        # Should not be 401 (assuming audit is enabled)
        assert resp.status_code != 401

    def test_session_reset_clears_keys(self, client):
        headers = {"X-PromptGuard-API-Key": "test-integration-key"}
        # Register a session key
        client.post(
            "/session/key",
            json={"key": "sk-reset-test"},
            headers=headers,
        )
        # Reset session
        resp = client.post("/session/reset", headers=headers)
        assert resp.status_code == 200
        # Keys should be cleared
        keys = client.get("/session/keys", headers=headers).json()["keys"]
        # After reset, session keys should be empty
        # Note: this also resets config, so the endpoint may need the key again
        # The key count should be 0 or the keys list empty
        assert len(keys) == 0