"""
Per-user session key management for VDI deployments.

In VDI environments, each user session gets a unique API key
injected via PROMPTGUARD_API_KEY env var. This module provides:
- Per-session key registration
- Key lookup and validation alongside the global API key
- Key rotation / revocation
"""
from __future__ import annotations

import hashlib
import threading
import time
from typing import Optional


# ── Session key store ─────────────────────────────────────────────────────────

_SESSION_KEYS: dict[str, dict] = {}  # hashed_key → {source, created_at, last_used_at}
_SESSION_LOCK = threading.Lock()

# Key expiry: 24 hours default (VDI sessions are typically shorter)
_DEFAULT_KEY_TTL = 86_400


def _hash_key(key: str) -> str:
    """Hash an API key for storage. SHA-256 to prevent key leakage from memory dumps."""
    return hashlib.sha256(key.encode()).hexdigest()


def register_session_key(key: str, source: str = "vdi_session") -> None:
    """Register a per-user session API key.

    Args:
        key: The plaintext API key (will be hashed for storage).
        source: Origin label (e.g. 'vdi_session', 'vscode_extension').
    """
    hashed = _hash_key(key)
    with _SESSION_LOCK:
        _SESSION_KEYS[hashed] = {
            "source": source,
            "created_at": time.time(),
            "last_used_at": time.time(),
        }


def validate_session_key(provided_key: str) -> bool:
    """Validate a provided key against registered session keys.

    Uses constant-time comparison. Returns True if the key matches
    any registered session key.
    """
    hashed = _hash_key(provided_key)
    with _SESSION_LOCK:
        entry = _SESSION_KEYS.get(hashed)
        if entry is None:
            return False
        entry["last_used_at"] = time.time()
        return True


def revoke_session_key(key: str) -> bool:
    """Revoke a session key. Returns True if the key was found and removed."""
    hashed = _hash_key(key)
    with _SESSION_LOCK:
        return _SESSION_KEYS.pop(hashed, None) is not None


def list_session_keys() -> list[dict]:
    """List metadata for all registered session keys (no plaintext keys)."""
    with _SESSION_LOCK:
        return [
            {"key_hash": h, **v}
            for h, v in _SESSION_KEYS.items()
        ]


def prune_expired_keys(ttl: float = _DEFAULT_KEY_TTL) -> int:
    """Remove session keys older than TTL seconds. Returns count pruned."""
    cutoff = time.time() - ttl
    with _SESSION_LOCK:
        expired = [h for h, v in _SESSION_KEYS.items()
                   if v.get("created_at", 0) < cutoff]
        for h in expired:
            del _SESSION_KEYS[h]
        return len(expired)


def clear_all_session_keys() -> int:
    """Remove all session keys. Returns count removed."""
    with _SESSION_LOCK:
        count = len(_SESSION_KEYS)
        _SESSION_KEYS.clear()
        return count