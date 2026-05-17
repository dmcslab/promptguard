"""
PromptGuard — FastAPI Service
Provider-agnostic proxy with workspace validation endpoints.
"""
from __future__ import annotations
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from fastapi.responses import JSONResponse
from promptguard.config import PromptGuardConfig, load_config, _validate_command_name
from promptguard.lifecycle import (
    init_session, get_session_id, request_shutdown, is_shutdown_requested,
    reset_session, session_info, drain_and_shutdown,
)
from promptguard.models import (
    ProxyRequest, HealthResponse,
    InstructionFileRequest, InstructionFileResponse,
    PreToolHookRequest,
    Decision, ViolationSummary,
)
from promptguard.pipeline import build_context, run_pipeline
from promptguard.pipeline.instr_validator import validate_instruction_file
from promptguard.providers_registry import (
    provider_from_string, get_spec, get_instruction_files,
    detect_provider, PROVIDER_REGISTRY,
)
from promptguard.audit.logger import AuditLogger
from promptguard.mcp_gateway import (
    MCPToolCall, MCPToolResult, MCPGatewayDecision,
    pre_call as mcp_pre_call, post_call as mcp_post_call,
    process_mcp_results,
)
from promptguard.signing import (
    EnforcementMode, SigningResult, PolicySigningError,
    verify_or_raise,
)

VERSION = "0.2.0"

_config: PromptGuardConfig | None = None
_audit: AuditLogger | None = None
_signing_result: SigningResult | None = None

# ── Rate limiter state ────────────────────────────────────────────────────────
import collections
import hmac
import pathlib


def _sanitize_path(path: str | None, max_length: int = 512) -> str | None:
    """Canonicalize and validate a file path to prevent path traversal.

    Rejects absolute paths, paths containing '..' or backslash, and paths
    that resolve outside the current working directory when relative.
    Returns the sanitized path string or None if input is None.
    """
    if path is None:
        return None
    if len(path) > max_length:
        raise HTTPException(status_code=400, detail=f"Path exceeds maximum length ({max_length}).")
    # Reject backslashes (Windows path separator / traversal)
    if "\\" in path:
        raise HTTPException(status_code=400, detail="Backslash not allowed in paths.")
    # Reject absolute paths
    if pathlib.PurePosixPath(path).is_absolute():
        raise HTTPException(status_code=400, detail="Absolute paths are not allowed.")
    # Resolve and ensure no directory traversal
    resolved = pathlib.Path(path).resolve()
    cwd = pathlib.Path.cwd().resolve()
    try:
        resolved.relative_to(cwd)
    except ValueError:
        raise HTTPException(status_code=400, detail="Path traversal detected.")
    return path
import hmac
import threading

_rate_lock = threading.Lock()
_rate_windows: dict[str, collections.deque] = collections.defaultdict(collections.deque)


def _rate_limit_key(request: Request) -> str:
    """Identify the rate-limit bucket: per X-Workspace-ID header or global."""
    return request.headers.get("X-Workspace-ID", "__global__")


def _check_rate_limit(key: str, rpm: int) -> None:
    """Sliding window rate limit. Raises HTTPException(429) if exceeded."""
    now = time.monotonic()
    window = 60.0  # 1 minute sliding window
    with _rate_lock:
        # Periodically sweep stale keys to prevent unbounded memory growth
        # from high-cardinality workspace IDs (TD-1 / ARGUS-PG2-001)
        if len(_rate_windows) > 1000:
            stale = [k for k, v in _rate_windows.items() if not v]
            for k in stale:
                del _rate_windows[k]

        dq = _rate_windows[key]
        # Evict entries older than the window
        while dq and now - dq[0] > window:
            dq.popleft()
        if len(dq) >= rpm:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {rpm} requests per minute for workspace '{key}'",
            )
        dq.append(now)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _config, _audit, _signing_result
    _config = init_session()
    _audit = AuditLogger(_config.audit)

    # ── Policy bundle signing verification ────────────────────────────────────
    mode = EnforcementMode(_config.signing.enforcement)
    config_path = getattr(_config, "_resolved_config_path", None)

    try:
        _signing_result = verify_or_raise(
            config_path=config_path,
            key_path=_config.signing.key_path,
            mode=mode,
        )
        if _signing_result.verified:
            sig_info = (
                f"signed ({_signing_result.sig_ts[:10]})"
                if _signing_result.sig_ts
                else "built-in defaults (unsigned)"
            )
            print(f"[PromptGuard] Policy signature: ✓ {sig_info}")
        else:
            print(f"[PromptGuard] Policy signature: ⚠ UNVERIFIED — {_signing_result.error}")
    except PolicySigningError as e:
        # Strict mode — fail closed, do not start
        print(f"[PromptGuard] FATAL: {e}")
        raise RuntimeError(f"PromptGuard refusing to start: policy signature invalid.\n{e}") from e

    print(f"[PromptGuard] v{VERSION} — {len(_config.rules)} rules | "
          f"signing={mode.value} | "
          f"providers: {', '.join(p.value for p in PROVIDER_REGISTRY)}")
    yield
    if _audit:
        _audit.shutdown()
    print("[PromptGuard] Shutting down.")


app = FastAPI(
    title="PromptGuard",
    version=VERSION,
    description=(
        "Provider-agnostic prompt precompiler — security and guardrails for "
        "AI-assisted development (Claude Code, GitHub Copilot, Continue, Cursor, Codeium)."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def shutdown_middleware(request: Request, call_next):
    """Reject new requests with 503 when service is shutting down.

    Health, readiness, and liveness probes are always allowed through.
    """
    if is_shutdown_requested():
        # Always allow meta endpoints during drain
        if request.url.path in ("/health", "/ready", "/live"):
            return await call_next(request)
        return JSONResponse(status_code=503, content={"detail": "Service shutting down, no new requests accepted"})
    return await call_next(request)


def get_config() -> PromptGuardConfig:
    if _config is None:
        raise HTTPException(503, "Server not ready")
    return _config


def get_audit() -> AuditLogger:
    if _audit is None:
        raise HTTPException(503, "Server not ready")
    return _audit


def get_signing() -> SigningResult | None:
    return _signing_result


# ── API Key auth dependency ───────────────────────────────────────────────────

def require_api_key(request: Request) -> None:
    """Validate X-PromptGuard-API-Key header against global or session keys.

    Checks the provided key against:
    1. The global PROMPTGUARD_API_KEY (if configured)
    2. Per-user session keys (if registered)

    Uses constant-time comparison with length normalization to prevent
    both timing attacks and length-leakage. If no key is configured
    and no session keys are registered, auth is skipped (backward compatible).
    """
    from promptguard.session_keys import validate_session_key
    cfg = _config
    if cfg is None:
        return  # Server not ready yet, let it through to 503 handler
    expected = cfg.providers.api_key
    if not expected:
        return  # No key configured — auth disabled
    provided = request.headers.get("X-PromptGuard-API-Key")
    if not provided:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    # Check global key first (constant-time)
    max_len = max(len(provided), len(expected))
    padded_provided = provided.ljust(max_len)
    padded_expected = expected.ljust(max_len)
    if hmac.compare_digest(padded_provided, padded_expected):
        return
    # Then check session keys
    if validate_session_key(provided):
        return
    raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ── Meta ──────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["meta"])
async def health(config: PromptGuardConfig = Depends(get_config)):
    """Component-level health check."""
    components: dict[str, str | dict] = {}
    overall = "ok"

    # Config
    try:
        _ = config.rules  # basic sanity
        components["config"] = "ok"
    except Exception as e:
        components["config"] = {"status": "error", "detail": str(e)}
        overall = "degraded"

    # Pipeline
    try:
        from promptguard.pipeline import build_context, run_pipeline
        components["pipeline"] = "ok"
    except Exception as e:
        components["pipeline"] = {"status": "error", "detail": str(e)}
        overall = "degraded"

    # Audit logger
    try:
        if _audit and _audit.enabled:
            components["audit_logger"] = "ok"
        elif _audit:
            components["audit_logger"] = "disabled"
        else:
            components["audit_logger"] = "not_initialized"
            overall = "degraded"
    except Exception as e:
        components["audit_logger"] = {"status": "error", "detail": str(e)}
        overall = "degraded"

    return {
        "status": overall,
        "components": components,
        "version": VERSION,
        "session": session_info(),
    }


@app.get("/ready", tags=["meta"])
async def readiness():
    """Readiness probe — returns 503 if shutting down, 200 otherwise."""
    if is_shutdown_requested():
        raise HTTPException(status_code=503, detail="Service shutting down")
    if _config is None:
        raise HTTPException(status_code=503, detail="Config not loaded")
    return {"status": "ready", "session": session_info()}


@app.get("/live", tags=["meta"])
async def liveness():
    """Liveness probe — always returns 200 if the process is alive."""
    return {"status": "alive"}


@app.post("/session/reset", tags=["meta"])
async def session_reset():
    """Reset all in-memory state for a fresh VDI session."""
    global _config, _audit, _signing_result
    from promptguard.session_keys import clear_all_session_keys, prune_expired_keys
    reset_session()
    clear_all_session_keys()
    _config = load_config()
    _audit = AuditLogger(_config.audit)
    return {"status": "reset", "session": session_info()}


# ── Session Key Management ───────────────────────────────────────────────────

@app.post("/session/key", tags=["session-keys"], dependencies=[Depends(require_api_key)])
async def register_key(request: Request):
    """Register a per-user session API key. Requires a valid global key to register.

    Body: {"key": "<new-session-key>", "source": "vdi_session"}
    The source field is optional and defaults to \"vdi_session\".
    """
    from promptguard.session_keys import register_session_key
    body = await request.json()
    key = body.get("key")
    if not key or not isinstance(key, str):
        raise HTTPException(status_code=400, detail="Field 'key' is required")
    source = body.get("source", "vdi_session")
    register_session_key(key, source=source)
    return {"status": "registered", "source": source}


@app.delete("/session/key", tags=["session-keys"], dependencies=[Depends(require_api_key)])
async def revoke_key(request: Request):
    """Revoke a session API key. Requires a valid global key.

    Body: {"key": "<session-key-to-revoke>"}
    """
    from promptguard.session_keys import revoke_session_key
    body = await request.json()
    key = body.get("key")
    if not key or not isinstance(key, str):
        raise HTTPException(status_code=400, detail="Field 'key' is required")
    removed = revoke_session_key(key)
    return {"status": "revoked" if removed else "not_found"}


@app.get("/session/keys", tags=["session-keys"], dependencies=[Depends(require_api_key)])
async def list_keys():
    """List metadata for all registered session keys. Returns hashes, not plaintext."""
    from promptguard.session_keys import list_session_keys, prune_expired_keys
    prune_expired_keys()  # Clean up expired keys on list
    return {"keys": list_session_keys()}


@app.get("/policy/signing-status", tags=["meta"])
async def signing_status():
    """Detailed policy bundle signing status — used by the VS Code extension status bar."""
    sig = _signing_result
    if sig is None:
        return {"verified": True, "mode": "off", "message": "Signing not configured"}
    return {
        "verified":     sig.verified,
        "mode":         sig.mode.value,
        "config_path":  sig.config_path,
        "sig_path":     sig.sig_path,
        "signed_at":    sig.sig_ts,
        "error":        sig.error,
        "message": (
            "Policy bundle signature verified ✓"
            if sig.verified
            else f"Policy bundle UNVERIFIED: {sig.error}"
        ),
    }


@app.post("/reload", tags=["meta"])
async def reload_config(_auth: None = Depends(require_api_key)):
    global _config, _audit, _signing_result
    _config = load_config()
    _audit = AuditLogger(_config.audit)

    # Re-verify signature on reload
    mode = EnforcementMode(_config.signing.enforcement)
    config_path = getattr(_config, "_resolved_config_path", None)
    try:
        _signing_result = verify_or_raise(
            config_path=config_path,
            key_path=_config.signing.key_path,
            mode=mode,
        )
    except PolicySigningError as e:
        raise HTTPException(status_code=403, detail=str(e))

    return {
        "status": "reloaded",
        "rules_loaded": len(_config.rules),
        "signing_verified": _signing_result.verified,
        "signing_mode": _signing_result.mode.value,
    }


# ── Workspace validation ──────────────────────────────────────────────────────

@app.post("/validate/instruction-file",
          response_model=InstructionFileResponse, tags=["validate"])
async def validate_instr_file(
    req: InstructionFileRequest,
    config: PromptGuardConfig = Depends(get_config),
):
    """
    Validate an AI instruction file (CLAUDE.md, copilot-instructions.md, etc.)
    Called by the WorkspaceGuardian on file open/change.
    """
    # Sanitize file path to prevent path traversal
    safe_path = _sanitize_path(req.file_path)
    provider = provider_from_string(req.provider)
    decision, findings, sanitized = validate_instruction_file(
        req.content, safe_path, provider, config
    )
    return InstructionFileResponse(
        decision=decision,
        findings=[
            ViolationSummary(
                rule_id=f.rule_id,
                severity=f.severity.value,
                message=f.message,
                decision=f.decision.value,
                stage=f.stage,
            )
            for f in findings
        ],
        sanitized_content=sanitized if decision != Decision.BLOCK_SESSION else None,
        provider=provider.value,
        file_path=safe_path,
    )


@app.get("/validate/workspace", tags=["validate"])
async def validate_workspace(
    workspace_root: str,
    config: PromptGuardConfig = Depends(get_config),
):
    """
    Scan a workspace root for all AI provider instruction files,
    validate each, and return a per-provider status map.
    Used by the VS Code extension on workspace open.
    """
    results = []
    for provider, path in get_instruction_files(workspace_root):
        content = path.read_text(errors="replace")
        decision, findings, _ = validate_instruction_file(
            content, str(path), provider, config
        )
        results.append({
            "provider": provider.value,
            "file": str(path),
            "decision": decision.value,
            "finding_count": len(findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "message": f.message,
                    "decision": f.decision.value,
                }
                for f in findings
            ],
        })

    detected = detect_provider(workspace_root)
    return {
        "workspace_root": workspace_root,
        "detected_providers": [p.value for p in detected],
        "instruction_file_results": results,
    }


# ── Hook endpoint (Claude Code PreToolUse) ────────────────────────────────────

@app.post("/hook/pre-tool", tags=["hook"])
async def pre_tool_hook(
    request: Request,
    req: PreToolHookRequest,
    config: PromptGuardConfig = Depends(get_config),
    audit: AuditLogger = Depends(get_audit),
    _auth: None = Depends(require_api_key),
):
    """
    Called by Claude Code PreToolUse hook.
    Payload: { tool_name, tool_input, session_id?, workspace_root? }
    Returns: { allowed: bool, reason?: str }
    Exit code semantics: 200+allowed=true → exit 0, allowed=false → exit 1
    """
    # Rate limiting
    rl_key = _rate_limit_key(request)
    _check_rate_limit(rl_key, config.rate_limit.requests_per_minute)

    tool_name = req.tool_name
    tool_input = str(req.tool_input) if req.tool_input is not None else ""
    # Sanitize workspace path to prevent path traversal
    _sanitize_path(req.workspace_root)
    workspace = req.workspace_root or rl_key

    t_start = time.monotonic()

    # Build a minimal context and run through policy
    proxy_req = ProxyRequest(
        prompt=f"[TOOL CALL] {tool_name}: {tool_input}",
        provider="claude_code",
        repo_root=req.workspace_root,
    )
    ctx = build_context(proxy_req)
    ctx = run_pipeline(ctx, config)

    allowed = ctx.decision != Decision.BLOCK_SESSION
    findings_list = [
        {"rule_id": f.rule_id, "severity": f.severity.value, "message": f.message}
        for f in ctx.all_findings
    ]
    redactions_list = [
        {"placeholder": r.placeholder, "pattern_name": r.pattern_name}
        for r in ctx.redactions
    ]
    response_ms = int((time.monotonic() - t_start) * 1000)

    # Structured audit log for hook requests
    if audit and audit.enabled:
        audit.log_hook(
            action="pre_tool_hook",
            decision=ctx.decision.value,
            workspace=workspace,
            tool_name=tool_name,
            findings=findings_list,
            redactions=redactions_list,
            response_ms=response_ms,
        )

    return {
        "allowed": allowed,
        "decision": ctx.decision.value,
        "reason": ctx.block_reason if not allowed else None,
        "findings": findings_list,
        "envelope": {
            "failClosed": config.fail_closed,
            "providers": config.providers.enabled,
            "policy_version": config.policy_version,
            "rate_limit_rpm": config.rate_limit.requests_per_minute,
        },
    }


# ── MCP Gateway ───────────────────────────────────────────────────────────────

@app.post("/mcp/pre-call", response_model=MCPGatewayDecision, tags=["mcp"])
async def mcp_validate_pre(
    call: MCPToolCall,
    config: PromptGuardConfig = Depends(get_config),
    _auth: None = Depends(require_api_key),
):
    """
    Gate an MCP tool call BEFORE it executes.
    Called by the VS Code extension or Claude Code hook before any MCP tool runs.

    Returns decision:
      ALLOW                → proceed, use sanitized_input
      ALLOW_WITH_REDACTION → proceed with secrets stripped from sanitized_input
      QUARANTINE           → do not execute, show warning to developer
      BLOCK_SESSION        → do not execute, session-level violation
    """
    result = mcp_pre_call(call, config)
    return result


@app.post("/mcp/post-call", response_model=MCPGatewayDecision, tags=["mcp"])
async def mcp_validate_post(
    result: MCPToolResult,
    config: PromptGuardConfig = Depends(get_config),
    _auth: None = Depends(require_api_key),
):
    """
    Sanitize an MCP tool response AFTER it executes, before it enters
    the AI's context window.

    Returns a ContextBlock (TrustLevel.TOOL_OUTPUT) with sanitized content.
    BLOCK_SESSION / QUARANTINE → context_block.included = False.
    """
    gw = mcp_post_call(result, config)
    return gw


@app.post("/mcp/process-batch", tags=["mcp"])
async def mcp_process_batch(
    results: list[MCPToolResult],
    config: PromptGuardConfig = Depends(get_config),
    _auth: None = Depends(require_api_key),
):
    """
    Process a list of MCP tool results into sanitized ContextBlocks
    ready for the pipeline classifier. Used when a full agentic loop
    produces multiple tool outputs before the next prompt.
    """
    blocks = process_mcp_results(results, config)
    return {
        "block_count": len(blocks),
        "included": sum(1 for b in blocks if b.included),
        "excluded": sum(1 for b in blocks if not b.included),
        "blocks": [
            {
                "source": b.source,
                "trust_level": b.trust_level.value,
                "sanitization_status": b.sanitization_status.value,
                "included": b.included,
                "exclusion_reason": b.exclusion_reason,
                "finding_count": len(b.findings),
                "content_hash": b.content_hash,
                "content_preview": b.content[:200] if b.included else None,
            }
            for b in blocks
        ],
    }


@app.get("/mcp/allowed-servers", tags=["mcp"])
async def mcp_allowed_servers(
    config: PromptGuardConfig = Depends(get_config),
):
    """Return the current MCP server allow-list."""
    return {
        "mcp_servers": config.allow_list.mcp_servers,
        "allowed_domains": config.allow_list.domains,
        "note": "Local servers (localhost, 127.0.0.1) are always allowed.",
    }


# ── Audit ──────────────────────────────────────────────────────────────────────

@app.get("/audit/stats", tags=["audit"])
async def audit_stats(audit: AuditLogger = Depends(get_audit)):
    return audit.stats()

@app.get("/audit/recent", tags=["audit"])
async def audit_recent(
    limit: int = 20,
    audit: AuditLogger = Depends(get_audit),
):
    return {"events": audit.recent(limit)}

@app.post("/audit/prune", tags=["audit"])
async def audit_prune(audit: AuditLogger = Depends(get_audit)):
    return {"pruned": audit.prune()}


# ── Helpers ───────────────────────────────────────────────────────────────────




@app.exception_handler(Exception)
async def _err(request: Request, exc: Exception):
    return JSONResponse(500, {"detail": f"{type(exc).__name__}: {exc}"})
