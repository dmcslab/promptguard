"""
Tests for PromptGuard SIEM Forwarder (TASK-094).

Covers:
- SIEMForwarder initialization, config, enabled/disabled
- Enqueue / batch accumulation
- Flush with retries and backoff
- Queue overflow / drop policy
- Auth header parsing
- Stats tracking
- AuditLogger integration (SIEM enqueue on log + log_hook)
"""
from __future__ import annotations

import json
import threading
import time
from unittest.mock import patch, MagicMock

import pytest

from promptguard.config import AuditConfig
from promptguard.audit.siem_forwarder import SIEMForwarder


class TestSIEMForwarderInit:
    def test_disabled_when_no_url(self):
        cfg = AuditConfig()
        sf = SIEMForwarder(cfg)
        assert sf.enabled is False

    def test_enabled_when_url_set(self):
        cfg = AuditConfig(siem_url="https://siem.example.com/api/v1/ingest")
        sf = SIEMForwarder(cfg)
        assert sf.enabled is True

    def test_auth_header_parsed(self):
        cfg = AuditConfig(
            siem_url="https://siem.example.com",
            siem_auth_header="Authorization: Bearer tok-abc123",
        )
        sf = SIEMForwarder(cfg)
        assert sf._headers["Authorization"] == "Bearer tok-abc123"

    def test_auth_header_single_value_rejected(self):
        """Single-value auth headers (no colon) are now rejected with a warning."""
        cfg = AuditConfig(
            siem_url="https://siem.example.com",
            siem_auth_header="tok-abc123",
        )
        sf = SIEMForwarder(cfg)
        assert "Authorization" not in sf._headers
        assert "Content-Type" in sf._headers  # default header still present

    def test_custom_batch_size(self):
        cfg = AuditConfig(
            siem_url="https://siem.example.com",
            siem_batch_size=100,
        )
        sf = SIEMForwarder(cfg)
        assert sf._batch_size == 100

    def test_default_batch_size(self):
        cfg = AuditConfig(siem_url="https://siem.example.com")
        sf = SIEMForwarder(cfg)
        assert sf._batch_size == 50


class TestSIEMForwarderEnqueue:
    def test_enqueue_disabled_noop(self):
        cfg = AuditConfig()
        sf = SIEMForwarder(cfg)
        sf.enqueue({"event": "test"})  # Should not raise
        assert len(sf._queue) == 0

    def test_enqueue_adds_to_queue(self):
        cfg = AuditConfig(siem_url="https://siem.example.com")
        sf = SIEMForwarder(cfg)
        sf.enqueue({"event": "test"})
        assert len(sf._queue) == 1

    def test_enqueue_drops_oldest_on_overflow(self):
        cfg = AuditConfig(siem_url="https://siem.example.com")
        sf = SIEMForwarder(cfg)
        sf._queue = ["old"] * 10_000
        sf.enqueue({"event": "new"})
        assert len(sf._queue) == 10_000
        assert sf._dropped_count == 1


class TestSIEMForwarderFlush:
    def test_flush_posts_batch(self):
        cfg = AuditConfig(siem_url="https://siem.example.com/ingest")
        sf = SIEMForwarder(cfg)
        sf.enqueue({"@timestamp": "2025-01-01T00:00:00Z", "event": {"id": "1"}})
        sf.enqueue({"@timestamp": "2025-01-01T00:00:01Z", "event": {"id": "2"}})

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            sf._flush_batch()

        assert sf._sent_count == 2
        assert len(sf._queue) == 0

    def test_flush_retries_on_failure(self):
        cfg = AuditConfig(siem_url="https://siem.example.com/ingest", siem_max_retries=2)
        sf = SIEMForwarder(cfg)
        sf.enqueue({"event": "test"})

        with patch("urllib.request.urlopen", side_effect=Exception("connection refused")):
            sf._flush_batch()

        # After max retries + initial attempt, batch should be dropped
        assert sf._dropped_count == 1

    def test_flush_no_retry_on_auth_error(self):
        import urllib.error
        cfg = AuditConfig(siem_url="https://siem.example.com/ingest", siem_max_retries=3)
        sf = SIEMForwarder(cfg)
        sf.enqueue({"event": "test"})

        error = urllib.error.HTTPError("https://siem.example.com", 401, "Unauthorized", {}, None)
        with patch("urllib.request.urlopen", side_effect=error):
            sf._flush_batch()

        # Should not retry — 401 is fatal
        assert sf._error_count == 1
        assert sf._dropped_count == 0


class TestSIEMForwarderStartStop:
    def test_start_creates_thread(self):
        cfg = AuditConfig(siem_url="https://siem.example.com/ingest")
        sf = SIEMForwarder(cfg)
        sf.start()
        assert sf._started is True
        assert sf._thread is not None
        sf.stop()

    def test_stop_flushes_remaining(self):
        cfg = AuditConfig(siem_url="https://siem.example.com/ingest")
        sf = SIEMForwarder(cfg)

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        sf.enqueue({"event": "test"})

        with patch("urllib.request.urlopen", return_value=mock_response):
            sf.start()
            sf.stop()

        assert sf._sent_count == 1

    def test_disabled_start_is_noop(self):
        cfg = AuditConfig()
        sf = SIEMForwarder(cfg)
        sf.start()
        assert sf._started is False
        sf.stop()  # Should not raise


class TestSIEMForwarderStats:
    def test_stats_disabled(self):
        cfg = AuditConfig()
        sf = SIEMForwarder(cfg)
        stats = sf.stats
        assert stats["enabled"] is False
        assert stats["sent"] == 0

    def test_stats_enabled_with_url(self):
        cfg = AuditConfig(siem_url="https://siem.example.com/ingest")
        sf = SIEMForwarder(cfg)
        stats = sf.stats
        assert stats["enabled"] is True
        assert stats["url"] == "https://siem.example.com/ingest"

    def test_stats_track_sent_and_dropped(self):
        cfg = AuditConfig(siem_url="https://siem.example.com/ingest")
        sf = SIEMForwarder(cfg)
        sf._sent_count = 5
        sf._dropped_count = 2
        sf._error_count = 1
        stats = sf.stats
        assert stats["sent"] == 5
        assert stats["dropped"] == 2
        assert stats["errors"] == 1


class TestAuditLoggerSIEMIntegration:
    """Test that AuditLogger forwards events to SIEM when configured."""

    def test_log_enqueues_to_siem(self, tmp_path):
        cfg = AuditConfig(
            enabled=True,
            log_path=str(tmp_path / "audit.db"),
            siem_url="https://siem.example.com/ingest",
        )
        from promptguard.audit.logger import AuditLogger
        logger = AuditLogger(cfg)

        # The SIEM forwarder should be started
        assert logger._siem.enabled is True

        # Patch the flush method so we don't actually POST
        logger._siem.enqueue = MagicMock()
        logger._siem.start()

        from promptguard.models import PipelineContext, Finding, Severity, Decision, SafePromptEnvelope, AIProvider
        ctx = PipelineContext(
            raw_prompt="test prompt",
            provider=AIProvider.claude_code,
            language="python",
            decision=Decision.ALLOW,
        )
        ctx.all_findings = []
        ctx.context_blocks = []
        ctx.redactions = []
        ctx.envelope = SafePromptEnvelope(
            envelope_hash="abc123",
            policy_version="1",
            provider=AIProvider.claude_code,
        )

        logger.log("test-id", ctx, "response", [], 42)
        assert logger._siem.enqueue.called
        logger._siem.stop()

    def test_log_hook_enqueues_to_siem(self, tmp_path):
        cfg = AuditConfig(
            enabled=True,
            log_path=str(tmp_path / "audit.db"),
            json_log_path=str(tmp_path / "audit.jsonl"),
            siem_url="https://siem.example.com/ingest",
        )
        from promptguard.audit.logger import AuditLogger
        logger = AuditLogger(cfg)
        logger._siem.enqueue = MagicMock()
        logger._siem.start()

        logger.log_hook("pre_tool", "ALLOW", "ws-1", tool_name="Read")
        assert logger._siem.enqueue.called
        logger._siem.stop()

    def test_siem_stats_in_audit_stats(self, tmp_path):
        cfg = AuditConfig(
            enabled=True,
            log_path=str(tmp_path / "audit.db"),
            siem_url="https://siem.example.com/ingest",
        )
        from promptguard.audit.logger import AuditLogger
        logger = AuditLogger(cfg)
        stats = logger.stats()
        assert "siem" in stats
        assert stats["siem"]["enabled"] is True
        assert stats["siem"]["url"] == "https://siem.example.com/ingest"
        logger._siem.stop()