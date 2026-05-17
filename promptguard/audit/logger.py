"""
Audit Logger

Writes every pipeline execution to:
1. SQLite (fast, local, queryable via CLI)
2. NDJSON file (Elastic/SIEM-compatible, optional)

Schema matches the Implementation Guide §12 audit event format.
"""
from __future__ import annotations
import json
import sqlite3
import hashlib
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Generator

from promptguard.models import PipelineContext, Finding, Decision
from promptguard.config import AuditConfig
from promptguard.audit.siem_forwarder import SIEMForwarder

VERSION = "0.2"

# Characters that could enable injection in log viewers (HTML, SQL, shell)
_LOG_SANITIZE_RE = __import__("re").compile(r'[^\x09\x0a\x0d\x20-\x7e]')
_LOG_SANITIZE_TABLE = str.maketrans({
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
    "&": "&amp;",
    "%": "\\%",
    "_": "\\_",
    "\\": "\\\\",
})
_LOG_SANITIZE_TABLE = str.maketrans({"<": "\u003c", "\u003e": "\u003e", "\u0026": "\u0026", '"': "\u0022", "'": "\u0027"})


def _sanitize_log_value(value: str | None, max_length: int = 4096) -> str | None:
    """Sanitize a string value for safe inclusion in audit logs.

    Strips control characters, escapes HTML entities, and truncates
    to max_length to prevent injection in log viewers.
    """
    if value is None:
        return None
    v = _LOG_SANITIZE_RE.sub("", value)
    if len(v) > max_length:
        v = v[:max_length]
    return v.translate(_LOG_SANITIZE_TABLE)

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id                       TEXT PRIMARY KEY,
    timestamp                TEXT NOT NULL,
    provider                 TEXT,
    language                 TEXT,
    file_path                TEXT,
    repo_root                TEXT,
    branch                   TEXT,
    policy_version           TEXT,
    decision                 TEXT NOT NULL,
    block_reason             TEXT,
    redaction_count          INTEGER DEFAULT 0,
    findings_json            TEXT,
    included_sources_json    TEXT,
    excluded_sources_json    TEXT,
    compiled_prompt_hash     TEXT,
    response_hash            TEXT,
    duration_ms              INTEGER,
    envelope_hash            TEXT
);
CREATE INDEX IF NOT EXISTS idx_ts       ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_decision ON audit_log(decision);
CREATE INDEX IF NOT EXISTS idx_provider ON audit_log(provider);
"""

_INSERT_SQL = """
INSERT INTO audit_log (
    id, timestamp, provider, language, file_path, repo_root, branch,
    policy_version, decision, block_reason, redaction_count,
    findings_json, included_sources_json, excluded_sources_json,
    compiled_prompt_hash, response_hash, duration_ms, envelope_hash
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
"""

_PRUNE_SQL = "DELETE FROM audit_log WHERE timestamp < ?"


def _sha256_short(text: str | None) -> str | None:
    if not text:
        return None
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _validate_log_path(path: Path) -> Path:
    """Resolve and validate a log path to prevent traversal outside safe bases."""
    resolved = path.expanduser().resolve()
    safe_bases = [Path.home().resolve(), Path("/tmp").resolve(), Path.cwd().resolve()]
    for base in safe_bases:
        try:
            resolved.relative_to(base)
            return resolved
        except ValueError:
            continue
    raise ValueError(
        f"Log path {path} resolves to {resolved}, which is outside safe bases: {safe_bases}"
    )


class AuditLogger:
    def __init__(self, cfg: AuditConfig) -> None:
        self.enabled = cfg.enabled
        self.db_path = _validate_log_path(Path(cfg.log_path))
        self.json_log_path = _validate_log_path(Path(cfg.json_log_path)) if cfg.json_log_path else None
        self.retention_days = cfg.retention_days
        self._siem = SIEMForwarder(cfg)

        if self.enabled:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()
            if self.json_log_path:
                self.json_log_path.parent.mkdir(parents=True, exist_ok=True)
            self._siem.start()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(_CREATE_SQL)

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _build_event(
        self,
        audit_id: str,
        ctx: PipelineContext,
        response: str | None,
        response_findings: list[Finding],
        duration_ms: int,
    ) -> dict:
        """Build the Elastic-compatible audit event dict."""
        all_findings = ctx.all_findings + response_findings
        included_sources = [b.source for b in ctx.context_blocks if b.included]
        excluded_sources = [
            {"source": b.source, "reason": b.exclusion_reason}
            for b in ctx.context_blocks if not b.included
        ]

        envelope_hash = None
        compiled_prompt_hash = None
        if ctx.envelope:
            envelope_hash = ctx.envelope.envelope_hash
            compiled_prompt_hash = _sha256_short(ctx.envelope.render())

        return {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {
                "id": audit_id,
                "kind": "alert" if ctx.decision == Decision.BLOCK_SESSION else "event",
                "category": "process",
                "type": "info",
                "outcome": ctx.decision.value,
                "duration": duration_ms,
            },
            "promptguard": {
                "schema_version": VERSION,
                "policy_version": ctx.envelope.policy_version if ctx.envelope else "unknown",
                "provider": ctx.provider.value,
                "language": ctx.language,
                "file_path": _sanitize_log_value(ctx.file_path),
                "repo_root": _sanitize_log_value(ctx.repo_root),
                "branch": ctx.branch,
                "decision": ctx.decision.value,
                "block_reason": _sanitize_log_value(ctx.block_reason),
                "redaction_count": len(ctx.redactions),
                "envelope_hash": envelope_hash,
                "compiled_prompt_hash": compiled_prompt_hash,
                "response_hash": _sha256_short(response),
                "included_context_sources": included_sources,
                "excluded_context_sources": excluded_sources,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity.value,
                        "message": _sanitize_log_value(f.message),
                        "decision": f.decision.value,
                        "stage": f.stage,
                        "matched_control": f.matched_control,
                    }
                    for f in all_findings
                ],
            },
        }

    def log(
        self,
        audit_id: str,
        ctx: PipelineContext,
        response: str | None,
        response_findings: list[Finding],
        duration_ms: int,
    ) -> None:
        if not self.enabled:
            return

        event = self._build_event(audit_id, ctx, response, response_findings, duration_ms)
        pg = event["promptguard"]

        # SQLite write
        with self._conn() as conn:
            conn.execute(_INSERT_SQL, (
                audit_id,
                event["@timestamp"],
                pg["provider"],
                pg["language"],
                pg["file_path"],
                pg["repo_root"],
                pg["branch"],
                pg["policy_version"],
                pg["decision"],
                pg["block_reason"],
                pg["redaction_count"],
                json.dumps(pg["findings"]),
                json.dumps(pg["included_context_sources"]),
                json.dumps(pg["excluded_context_sources"]),
                pg["compiled_prompt_hash"],
                pg["response_hash"],
                duration_ms,
                pg["envelope_hash"],
            ))

        # NDJSON write (Elastic ingestion)
        if self.json_log_path:
            with open(self.json_log_path, "a") as f:
                f.write(json.dumps(event) + "\n")

        # SIEM forwarding
        self._siem.enqueue(event)

    def log_hook(
        self,
        action: str,
        decision: str,
        workspace: str,
        tool_name: str | None = None,
        findings: list[dict] | None = None,
        redactions: list[dict] | None = None,
        response_ms: int = 0,
    ) -> None:
        """Log a hook request as ECS-compatible JSON line."""
        if not self.enabled:
            return
        if not self.json_log_path:
            return

        event_id = str(uuid.uuid4())

        event = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {
                "id": event_id,
                "kind": "alert" if decision == "BLOCK_SESSION" else "event",
                "category": "process",
                "type": "info",
                "outcome": decision,
                "duration": response_ms,
            },
            "promptguard": {
                "schema_version": VERSION,
                "action": _sanitize_log_value(action),
                "decision": decision,
                "workspace": _sanitize_log_value(workspace),
                "tool_name": _sanitize_log_value(tool_name),
                "findings": [
                    {k: _sanitize_log_value(v) if isinstance(v, str) else v for k, v in f.items()}
                    for f in (findings or [])
                ],
                "redactions": redactions or [],
                "response_ms": response_ms,
            },
        }
        with open(self.json_log_path, "a") as f:
            f.write(json.dumps(event) + "\n")

        # SIEM forwarding
        self._siem.enqueue(event)

    def prune(self) -> int:
        if not self.enabled:
            return 0
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        ).isoformat()
        with self._conn() as conn:
            cur = conn.execute(_PRUNE_SQL, (cutoff,))
            return cur.rowcount

    def stats(self) -> dict:
        if not self.enabled:
            return {"enabled": False}
        with self._conn() as conn:
            row = conn.execute("""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN decision='BLOCK_SESSION' THEN 1 ELSE 0 END) AS blocked,
                    SUM(CASE WHEN decision='QUARANTINE' THEN 1 ELSE 0 END) AS quarantined,
                    SUM(CASE WHEN decision='ALLOW_WITH_REDACTION' THEN 1 ELSE 0 END) AS redacted,
                    SUM(redaction_count) AS total_redactions,
                    MAX(timestamp) AS last_request
                FROM audit_log
            """).fetchone()
        return dict(row) | {
            "enabled": True,
            "db_path": str(self.db_path),
            "siem": self._siem.stats,
        }

    def shutdown(self) -> None:
        """Flush SIEM forwarder and stop background thread."""
        self._siem.stop()

    def recent(self, limit: int = 20) -> list[dict]:
        if not self.enabled:
            return []
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, timestamp, provider, decision, block_reason, "
                "redaction_count, duration_ms FROM audit_log "
                "ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
