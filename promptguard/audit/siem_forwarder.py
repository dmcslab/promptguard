"""
SIEM Forwarder — POSTs Elastic Common Schema (ECS) JSON audit events
to a remote HTTP endpoint (Elastic, Splunk HEC, Datadog, etc.).

Features:
- Async batched forwarding with configurable flush interval and batch size
- Retry with exponential backoff
- Non-blocking: failures are logged but never block the pipeline
- Configurable via .promptguard.yaml audit section
"""
from __future__ import annotations

import json
import logging
import random
import threading
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

from promptguard.config import AuditConfig

logger = logging.getLogger("promptguard.siem")

# ── Defaults ──────────────────────────────────────────────────────────────────
_DEFAULT_BATCH_SIZE = 50
_DEFAULT_FLUSH_INTERVAL = 5.0       # seconds
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BACKOFF_BASE = 1.0         # seconds
_DEFAULT_TIMEOUT = 10.0              # seconds
_MAX_QUEUE_SIZE = 10_000             # drop events if queue backs up


class SIEMForwarder:
    """Forward audit events to a remote SIEM/HTTP endpoint.

    Events are buffered and sent in batches to minimize network overhead.
    Failed batches are retried with exponential backoff up to max_retries.
    If the queue exceeds _MAX_QUEUE_SIZE, oldest events are dropped.
    """

    def __init__(self, cfg: AuditConfig) -> None:
        self._url: str | None = cfg.siem_url
        self._headers: dict[str, str] = {"Content-Type": "application/json"}
        if cfg.siem_auth_header:
            # e.g. "Authorization: Bearer tok-abc123" or "X-Splunk-Auth: token"
            parts = cfg.siem_auth_header.split(":", 1)
            if len(parts) != 2:
                logger.warning("[SIEM] siem_auth_header is not a valid 'Header: Value' pair")
            else:
                hname = parts[0].strip()
                # Reject security-sensitive header injection
                _UNSAFE_HEADERS = frozenset({"content-length", "host", "transfer-encoding"})
                if hname.lower() in _UNSAFE_HEADERS:
                    logger.warning("[SIEM] refusing unsafe header name: %s", hname)
                else:
                    self._headers[hname] = parts[1].strip()

        self._batch_size = cfg.siem_batch_size or _DEFAULT_BATCH_SIZE
        self._flush_interval = cfg.siem_flush_interval or _DEFAULT_FLUSH_INTERVAL
        self._max_retries = cfg.siem_max_retries or _DEFAULT_MAX_RETRIES
        self._backoff_base = _DEFAULT_BACKOFF_BASE
        self._timeout = _DEFAULT_TIMEOUT

        self._queue: list[str] = []          # JSON-encoded event lines
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._started = False

        # Track forwarding stats
        self._sent_count = 0
        self._dropped_count = 0
        self._error_count = 0

    @property
    def enabled(self) -> bool:
        return bool(self._url)

    @property
    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": self.enabled,
                "url": self._url or "",
                "sent": self._sent_count,
                "dropped": self._dropped_count,
                "errors": self._error_count,
                "queued": len(self._queue),
            }

    def start(self) -> None:
        """Start the background flush thread."""
        if not self._url or self._started:
            return
        self._started = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._flush_loop,
            name="promptguard-siem-forwarder",
            daemon=True,
        )
        self._thread.start()
        logger.info("[SIEM] Forwarder started → %s (batch=%d, flush=%.1fs)",
                     self._url, self._batch_size, self._flush_interval)

    def stop(self) -> None:
        """Stop the background thread, flushing any remaining events."""
        if not self._started:
            return
        self._stop_event.set()
        # Wait for background thread to finish current flush interval
        if self._thread:
            self._thread.join(timeout=self._flush_interval + 2.0)
        # Drain any remaining events synchronously (some may have arrived during join)
        for _ in range(3):
            if not self._queue:
                break
            self._flush_batch()
        self._started = False
        logger.info("[SIEM] Forwarder stopped. sent=%d dropped=%d errors=%d",
                     self._sent_count, self._dropped_count, self._error_count)

    def enqueue(self, event: dict) -> None:
        """Add an ECS event dict to the forwarding queue.

        Thread-safe, non-blocking. Drops oldest events if queue is full.
        """
        if not self._url:
            return

        line = json.dumps(event, default=str)
        with self._lock:
            if len(self._queue) >= _MAX_QUEUE_SIZE:
                self._queue.pop(0)
                self._dropped_count += 1
                logger.warning("[SIEM] Queue overflow: dropped oldest event (queued=%d)", _MAX_QUEUE_SIZE)
            self._queue.append(line)

    def _flush_loop(self) -> None:
        """Background thread: flush queued events at the configured interval."""
        while not self._stop_event.is_set():
            self._stop_event.wait(self._flush_interval)
            self._flush_batch()

    def _flush_batch(self) -> None:
        """Drain up to batch_size events from the queue and POST them.

        Thread safety: batch is captured under self._lock, then I/O happens
        outside the lock to avoid blocking enqueue() during network calls.
        """
        with self._lock:
            batch = self._queue[:self._batch_size]
            self._queue = self._queue[self._batch_size:]
        # Exit lock before I/O — batch is now a local snapshot
        if not batch:
            return
        payload = "\n".join(batch)
        body = payload.encode("utf-8")

        for attempt in range(self._max_retries + 1):
            try:
                req = urllib.request.Request(
                    self._url,
                    data=body,
                    headers=self._headers,
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    if resp.status >= 300:
                        logger.warning("[SIEM] Forward returned %d", resp.status)
                        self._error_count += 1
                    else:
                        self._sent_count += len(batch)
                        return
            except urllib.error.HTTPError as e:
                logger.warning("[SIEM] HTTP %d forwarding batch (%d events): %s",
                               e.code, len(batch), e.reason)
                self._error_count += 1
                if e.code in (401, 403, 404):
                    return  # Don't retry auth/config errors
            except Exception as e:
                logger.warning("[SIEM] Forward error (attempt %d/%d): %s",
                               attempt + 1, self._max_retries + 1, e)
                self._error_count += 1

            if attempt < self._max_retries:
                backoff = self._backoff_base * (2 ** attempt) * (0.5 + random.random())
                time.sleep(backoff)

        # All retries exhausted — drop the batch
        self._dropped_count += len(batch)
        logger.error("[SIEM] Dropped %d events after %d retries", len(batch), self._max_retries)