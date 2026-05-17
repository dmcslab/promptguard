"""
MCP Gateway — §11 Implementation

Intercepts every MCP tool call at two points:

  PRE-CALL  (before the tool runs):
    - Validate the MCP server URL against the allow-list
    - Scan tool input arguments for injection, secrets, risky file refs
    - Apply the 4-way decision: ALLOW / REDACT / QUARANTINE / BLOCK

  POST-CALL (after the tool returns):
    - Scan the tool response for secrets, injections, dangerous patterns
    - Assign TrustLevel.TOOL_OUTPUT to the response block
    - Strip or annotate dangerous content before it enters Stage 2 (classifier)

The gateway runs as a standalone FastAPI sub-application mounted at /mcp
and is also callable inline from the main pipeline when MCP context blocks
are passed with a ProxyRequest.
"""
from __future__ import annotations
import re
import json
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

from pydantic import BaseModel, Field
from promptguard.models import (
    ContextBlock, ContentType, TrustLevel, SanitizationStatus,
    Finding, Severity, Decision, RedactionRecord,
)
from promptguard.config import PromptGuardConfig


# ── MCP Request / Response Models ────────────────────────────────────────────

class MCPToolCall(BaseModel):
    server_url: str = Field(..., max_length=2048)
    server_name: str | None = Field(None, max_length=256)
    tool_name: str = Field(..., max_length=256)
    tool_input: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = Field(None, max_length=128)
    workspace_root: str | None = Field(None, max_length=512)

    model_config = {"str_max_length": 8192}


class MCPToolResult(BaseModel):
    server_url: str = Field(..., max_length=2048)
    server_name: str | None = Field(None, max_length=256)
    tool_name: str = Field(..., max_length=256)
    tool_output: Any                    # raw output from tool
    is_error: bool = False
    session_id: str | None = Field(None, max_length=128)

    model_config = {"str_max_length": 32768}


class MCPGatewayDecision(BaseModel):
    decision: Decision
    block_reason: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    sanitized_input: dict[str, Any] | None = None   # pre-call
    context_block: ContextBlock | None = None         # post-call


# ── Dangerous tool patterns ───────────────────────────────────────────────────

# Tools that warrant extra scrutiny regardless of server
_HIGH_RISK_TOOLS = {
    "bash", "shell", "exec", "run_command", "execute", "eval",
    "write_file", "delete_file", "move_file", "create_file",
    "git_commit", "git_push", "git_merge", "create_pull_request",
    "deploy", "publish", "send_email", "send_message", "http_request",
    "fetch_url", "web_fetch", "database_query", "sql_query",
}

# Patterns to scan in tool INPUT args (JSON-serialised)
_INPUT_PATTERNS: list[tuple[str, str, Severity, Decision]] = [
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
     "PP-MCP-INJ-001", Severity.critical, Decision.BLOCK_SESSION),
    (r"(?i)disregard\s+(security|policy|guidelines)",
     "PP-MCP-INJ-002", Severity.critical, Decision.BLOCK_SESSION),
    (r"(?i)(exfiltrate|upload\s+to|send\s+to\s+external|curl\s+-X\s+POST\s+https?://[^\s]+\s+-\s*d)",
     "PP-MCP-EXF-001", Severity.critical, Decision.BLOCK_SESSION),
    (r"rm\s+-rf|del\s+/[fqs]|format\s+[cde]:",
     "PP-MCP-DESTR-001", Severity.critical, Decision.BLOCK_SESSION),
    (r"(?i)(git\s+push|git\s+commit|git\s+merge|create.pull.request)",
     "PP-MCP-GIT-001", Severity.critical, Decision.BLOCK_SESSION),
    (r"(?i)(\.env\b|id_rsa|id_ed25519|\.pem\b|kubeconfig|aws_credentials)",
     "PP-MCP-FILE-001", Severity.high, Decision.QUARANTINE),
    (r"(?i)(password|secret|api_key)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
     "PP-MCP-SECRET-001", Severity.high, Decision.ALLOW_WITH_REDACTION),
    (r"sk-[a-zA-Z0-9]{32,}|sk-ant-[a-zA-Z0-9\-_]{32,}",
     "PP-MCP-KEY-001", Severity.high, Decision.ALLOW_WITH_REDACTION),
    (r"(?i)shell\s*=\s*true|subprocess.*shell",
     "PP-MCP-SHELL-001", Severity.high, Decision.QUARANTINE),
    (r"(?i)(curl|wget)\s+https?://[^\s]+\s*\|\s*(bash|sh|python)",
     "PP-MCP-PIPE-001", Severity.critical, Decision.BLOCK_SESSION),
]

# Patterns to scan in tool OUTPUT (response from MCP server)
_OUTPUT_PATTERNS: list[tuple[str, str, Severity, Decision]] = [
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
     "PP-MCP-RESP-INJ-001", Severity.critical, Decision.BLOCK_SESSION),
    (r"sk-[a-zA-Z0-9]{32,}|sk-ant-[a-zA-Z0-9\-_]{32,}",
     "PP-MCP-RESP-KEY-001", Severity.high, Decision.ALLOW_WITH_REDACTION),
    (r"AKIA[0-9A-Z]{16}",
     "PP-MCP-RESP-AWS-001", Severity.high, Decision.ALLOW_WITH_REDACTION),
    (r"(?i)(password|passwd|secret)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
     "PP-MCP-RESP-SECRET-001", Severity.high, Decision.ALLOW_WITH_REDACTION),
    (r"(?i)(exfiltrate|upload\s+to\s+external|send\s+to\s+http)",
     "PP-MCP-RESP-EXF-001", Severity.critical, Decision.BLOCK_SESSION),
    (r"(?i)you\s+are\s+now\s+(DAN|jailbroken|unrestricted)",
     "PP-MCP-RESP-JAILBREAK-001", Severity.critical, Decision.BLOCK_SESSION),
    (r"(?i)(disable|bypass|suppress)\s+(security|monitoring|logging)",
     "PP-MCP-RESP-SEC-001", Severity.high, Decision.QUARANTINE),
]

_DECISION_ORDER = [
    Decision.ALLOW,
    Decision.ALLOW_WITH_REDACTION,
    Decision.QUARANTINE,
    Decision.BLOCK_SESSION,
]


def _escalate(a: Decision, b: Decision) -> Decision:
    return _DECISION_ORDER[max(_DECISION_ORDER.index(a), _DECISION_ORDER.index(b))]


# ── Server URL allow-list check ───────────────────────────────────────────────

def _server_allowed(server_url: str, config: PromptGuardConfig) -> bool:
    """Check MCP server URL against config allow-list."""
    # Validate URL format first
    if not server_url or not re.match(r'^https?://[^\s/]+', server_url):
        return False

    # Local servers always allowed
    try:
        parsed = urlparse(server_url)
        host = parsed.hostname or ""
        if host in ("localhost", "127.0.0.1", "::1") or host.startswith("192.168."):
            return True
    except Exception:
        return False

    # Check explicit MCP server allow-list
    for allowed in config.allow_list.mcp_servers:
        if server_url.startswith(allowed) or server_url == allowed:
            return True

    # Fall back to domain allow-list
    try:
        host = urlparse(server_url).hostname or ""
        for d in config.allow_list.domains:
            if host == d or host.endswith("." + d):
                return True
    except Exception:
        return False

    return False


# ── Secret redaction in string ────────────────────────────────────────────────

_SECRET_RE = re.compile(
    r"(?i)(sk-[a-zA-Z0-9]{32,}"
    r"|sk-ant-[a-zA-Z0-9\-_]{32,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9_]{36,}"
    r"|(?:password|secret|api_key)\s*[=:]\s*['\"][^'\"]{8,}['\"]"
    r")"
)

def _redact_string(text: str, redactions: list[RedactionRecord], counter: dict) -> str:
    def _sub(m: re.Match) -> str:
        counter["n"] = counter.get("n", 0) + 1
        ph = f"[REDACTED_MCP_SECRET_{counter['n']}]"
        redactions.append(RedactionRecord(placeholder=ph, pattern_name="mcp_secret"))
        return ph
    return _SECRET_RE.sub(_sub, text)


def _redact_value(val: Any, redactions: list[RedactionRecord], counter: dict) -> Any:
    """Recursively redact secrets from a JSON-serialisable value."""
    if isinstance(val, str):
        return _redact_string(val, redactions, counter)
    elif isinstance(val, dict):
        return {k: _redact_value(v, redactions, counter) for k, v in val.items()}
    elif isinstance(val, list):
        return [_redact_value(v, redactions, counter) for v in val]
    return val


# ── Pre-call gate ─────────────────────────────────────────────────────────────

def pre_call(call: MCPToolCall, config: PromptGuardConfig) -> MCPGatewayDecision:
    """
    Validate an MCP tool call before it executes.
    Returns a decision — BLOCK_SESSION means do not execute the tool.
    """
    findings: list[Finding] = []
    decision = Decision.ALLOW
    redactions: list[RedactionRecord] = []
    sanitized_input = dict(call.tool_input)

    # ── 1. Server URL allow-list ──────────────────────────────────────────────
    # Redact secrets from server_url before any logging or comparison
    redacted_url = _redact_string(call.server_url, redactions, counter) if "sk-" in call.server_url or "api_key" in call.server_url.lower() else call.server_url
    if not _server_allowed(call.server_url, config):
        findings.append(Finding(
            rule_id="PP-MCP-SERVER-001",
            severity=Severity.critical,
            message=f"MCP server is not on the allow-list.",
            matched_control="SEC-AI-001 H-11",
            decision=Decision.BLOCK_SESSION,
            stage="mcp_pre",
        ))
        decision = Decision.BLOCK_SESSION

    # ── 2. High-risk tool names ───────────────────────────────────────────────
    if call.tool_name.lower() in _HIGH_RISK_TOOLS:
        findings.append(Finding(
            rule_id="PP-MCP-HRTOOL-001",
            severity=Severity.medium,
            message=f"High-risk MCP tool '{call.tool_name}' — inputs will be strictly scanned.",
            decision=Decision.ALLOW,
            stage="mcp_pre",
        ))

    # ── 3. Scan serialised input for injection / dangerous patterns ───────────
    input_str = json.dumps(call.tool_input)
    for pattern, rule_id, severity, rule_decision in _INPUT_PATTERNS:
        match = re.search(pattern, input_str, re.IGNORECASE)
        if match:
            findings.append(Finding(
                rule_id=rule_id,
                severity=severity,
                message=f"MCP tool input contains policy violation: {rule_id}",
                matched_text=match.group(0)[:80],
                decision=rule_decision,
                stage="mcp_pre",
            ))
            decision = _escalate(decision, rule_decision)

    # ── 4. Redact secrets from input args (ALLOW_WITH_REDACTION path) ─────────
    if decision in (Decision.ALLOW, Decision.ALLOW_WITH_REDACTION):
        counter: dict = {}
        sanitized_input = _redact_value(call.tool_input, redactions, counter)
        if redactions:
            decision = _escalate(decision, Decision.ALLOW_WITH_REDACTION)

    # ── 5. Block check ────────────────────────────────────────────────────────
    block_reason: str | None = None
    if decision == Decision.BLOCK_SESSION:
        block_reason = (
            "MCP tool call blocked: "
            + "; ".join(f.message for f in findings if f.decision == Decision.BLOCK_SESSION)
        )
    elif decision == Decision.QUARANTINE:
        block_reason = (
            "MCP tool call quarantined: "
            + "; ".join(f.message for f in findings if f.severity in (Severity.critical, Severity.high))
        )

    return MCPGatewayDecision(
        decision=decision,
        block_reason=block_reason,
        findings=findings,
        sanitized_input=sanitized_input if decision != Decision.BLOCK_SESSION else None,
    )


# ── Post-call gate ────────────────────────────────────────────────────────────

def post_call(
    result: MCPToolResult,
    config: PromptGuardConfig,
) -> MCPGatewayDecision:
    """
    Scan an MCP tool response before it enters the pipeline context.
    Returns a ContextBlock (TrustLevel.TOOL_OUTPUT) with sanitized content.
    """
    findings: list[Finding] = []
    decision = Decision.ALLOW
    redactions: list[RedactionRecord] = []

    # Serialise output for scanning
    if isinstance(result.tool_output, str):
        raw_text = result.tool_output
    else:
        try:
            raw_text = json.dumps(result.tool_output, indent=2)
        except (TypeError, ValueError):
            raw_text = str(result.tool_output)

    # ── 1. Scan for injection / dangerous content in response ─────────────────
    for pattern, rule_id, severity, rule_decision in _OUTPUT_PATTERNS:
        match = re.search(pattern, raw_text, re.IGNORECASE)
        if match:
            findings.append(Finding(
                rule_id=rule_id,
                severity=severity,
                message=f"MCP tool response contains policy violation: {rule_id}",
                matched_text=match.group(0)[:80],
                decision=rule_decision,
                stage="mcp_post",
            ))
            decision = _escalate(decision, rule_decision)

    # ── 2. Redact secrets from response ──────────────────────────────────────
    counter: dict = {}
    sanitized_text = _redact_string(raw_text, redactions, counter)
    if redactions:
        decision = _escalate(decision, Decision.ALLOW_WITH_REDACTION)
        findings.append(Finding(
            rule_id="PP-MCP-RESP-REDACT-001",
            severity=Severity.info,
            message=f"{len(redactions)} secret(s) redacted from MCP tool response.",
            decision=Decision.ALLOW_WITH_REDACTION,
            stage="mcp_post",
        ))

    # ── 3. Determine sanitization status and inclusion ────────────────────────
    if decision == Decision.BLOCK_SESSION:
        status = SanitizationStatus.blocked
        included = False
        block_reason = (
            "MCP response blocked — contains critical policy violation(s): "
            + "; ".join(f.message for f in findings if f.decision == Decision.BLOCK_SESSION)
        )
        # Replace entire content with summary
        sanitized_text = f"[MCP RESPONSE BLOCKED by PromptGuard: {block_reason}]"
    elif decision == Decision.QUARANTINE:
        status = SanitizationStatus.quarantined
        included = False
        block_reason = "MCP response quarantined — high-severity findings."
        sanitized_text = f"[MCP RESPONSE QUARANTINED: {block_reason}]"
    elif decision == Decision.ALLOW_WITH_REDACTION:
        status = SanitizationStatus.redacted
        included = True
        block_reason = None
    else:
        status = SanitizationStatus.passed
        included = True
        block_reason = None

    source = f"mcp:{result.server_name or result.server_url}/{result.tool_name}"
    block = ContextBlock(
        source=source,
        content_type=ContentType.mcp_response,
        trust_level=TrustLevel.TOOL_OUTPUT,
        sanitization_status=status,
        content=sanitized_text,
        original_hash=ContextBlock.make_hash(raw_text),
        content_hash=ContextBlock.make_hash(sanitized_text),
        contains_secrets=bool(redactions),
        findings=findings,
        included=included,
        exclusion_reason=block_reason if not included else None,
    )

    return MCPGatewayDecision(
        decision=decision,
        block_reason=block_reason,
        findings=findings,
        context_block=block,
    )


# ── Batch helper: process multiple MCP results into context blocks ─────────────

def process_mcp_results(
    results: list[MCPToolResult],
    config: PromptGuardConfig,
) -> list[ContextBlock]:
    """
    Process a list of MCP tool results into sanitized ContextBlocks
    ready for Stage 2 (classifier) of the main pipeline.
    """
    blocks: list[ContextBlock] = []
    for result in results:
        gateway_result = post_call(result, config)
        if gateway_result.context_block:
            blocks.append(gateway_result.context_block)
    return blocks
