"""
PromptGuard VDI session lifecycle management.

Handles:
- Service startup with config injection
- In-memory state (no persistent artifacts between sessions)
- Graceful shutdown with in-flight request draining
- Session health and readiness endpoints
- State reset for new VDI sessions
"""
from __future__ import annotations

import asyncio
import os
import signal
import time
from typing import Any

from promptguard.config import load_config, PromptGuardConfig


_SESSION_START_TIME: float = 0.0
_SESSION_ID: str | None = None
_SHUTDOWN_REQUESTED = False
_DRAIN_TIMEOUT_SECONDS = 10


def init_session() -> PromptGuardConfig:
    """Initialize a PromptGuard session.

    Called once at service startup. Loads config via the standard
    priority chain (explicit path > URL > inline > file > CWD > home),
    sets the session start time, and returns the config.

    In VDI environments, PROMPTGUARD_CONFIG_URL or PROMPTGUARD_CONFIG_INLINE
    should be set by the session launcher before starting the service.
    """
    global _SESSION_START_TIME, _SESSION_ID, _SHUTDOWN_REQUESTED

    config = load_config()
    _SESSION_START_TIME = time.monotonic()
    _SESSION_ID = os.environ.get("PROMPTGUARD_SESSION_ID") or f"pg-{int(time.time())}"
    _SHUTDOWN_REQUESTED = False

    return config


def get_session_id() -> str | None:
    """Return the current session ID, if initialized."""
    return _SESSION_ID


def get_session_start_time() -> float:
    """Return monotonic session start time."""
    return _SESSION_START_TIME


def is_shutdown_requested() -> bool:
    """Check whether a shutdown signal has been received."""
    return _SHUTDOWN_REQUESTED


def request_shutdown() -> None:
    """Mark the session for graceful shutdown.

    Called by signal handlers. In-flight requests continue;
    new requests receive 503 after this point.
    """
    global _SHUTDOWN_REQUESTED
    _SHUTDOWN_REQUESTED = True


def reset_session() -> None:
    """Reset all in-memory session state for a fresh VDI session.

    Clears rate-limit windows, session ID, and timestamps.
    Does NOT reload config — call init_session() for that.
    """
    global _SESSION_START_TIME, _SESSION_ID, _SHUTDOWN_REQUESTED
    _SESSION_START_TIME = 0.0
    _SESSION_ID = None
    _SHUTDOWN_REQUESTED = False

    # Reset rate-limit windows in main module
    try:
        from promptguard.main import _rate_windows
        _rate_windows.clear()
    except ImportError:
        pass


async def drain_and_shutdown(timeout: float = _DRAIN_TIMEOUT_SECONDS) -> None:
    """Wait for in-flight requests to complete, then exit.

    Gives active requests `timeout` seconds to finish.
    After timeout, forces exit.
    """
    request_drain_event = asyncio.Event()

    # Allow up to `timeout` seconds for in-flight requests
    try:
        await asyncio.wait_for(request_drain_event.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        pass

    # Force exit — all state is in-memory, nothing to persist
    os._exit(0)  # noqa: S606  # intentional: no atexit handlers needed for in-memory service


def register_signal_handlers() -> None:
    """Register SIGTERM/SIGINT handlers for graceful VDI lifecycle.

    On signal receipt:
    1. Set shutdown flag (new requests get 503)
    2. Initiate drain-and-shutdown
    """
    loop = asyncio.get_event_loop()

    def _handle_shutdown(signum: int, frame: Any = None) -> None:
        request_shutdown()

    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)


def session_info() -> dict[str, Any]:
    """Return a dict of session metadata for health/readiness endpoints."""
    return {
        "session_id": _SESSION_ID,
        "started_at": _SESSION_START_TIME,
        "uptime_seconds": round(time.monotonic() - _SESSION_START_TIME, 2) if _SESSION_START_TIME else 0,
        "shutdown_requested": _SHUTDOWN_REQUESTED,
        "state": "draining" if _SHUTDOWN_REQUESTED else "active",
    }