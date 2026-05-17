"""
Stage 4 — Redactor

Scans all context blocks for secrets, API keys, PII, and
high-entropy tokens. Replaces with stable placeholders.
Original values are never stored — only the placeholder mapping
is retained for response restoration.
"""
from __future__ import annotations
import math
import re
from promptguard.models import (
    PipelineContext, RedactionRecord, ContextBlock,
    SanitizationStatus, Finding, Severity, Decision,
)
from promptguard.config import PromptGuardConfig

# ── Secret patterns ───────────────────────────────────────────────────────────
_SECRET_PATTERNS: list[tuple[str, str]] = [
    ("openai_key",       r"sk-[a-zA-Z0-9]{32,}"),
    ("anthropic_key",    r"sk-ant-[a-zA-Z0-9\-_]{32,}"),
    ("github_pat",       r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    ("github_oauth",     r"gho_[A-Za-z0-9_]{36,}"),
    ("aws_access_key",   r"AKIA[0-9A-Z]{16}"),
    ("aws_secret",       r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"),
    ("stripe_key",       r"sk_(?:live|test)_[A-Za-z0-9]{24,}"),
    ("jwt",              r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
    ("basic_auth_url",   r"https?://[^:@\s]+:[^@\s]+@"),
    ("private_key_block",r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("db_url",           r"(?i)(?:postgres|mysql|mongodb|redis|mssql)://[^\s\"']+"),
    ("generic_secret",   r"(?i)(?:password|passwd|secret|api[_\-]?key|access[_\-]?token)\s*[=:]\s*['\"]([^'\"]{8,})['\"]"),
    ("azure_key",        r"(?i)AccountKey=[A-Za-z0-9+/=]{44}"),
    ("google_api_key",   r"AIza[A-Za-z0-9_\-]{35}"),
]

# ── PII patterns ──────────────────────────────────────────────────────────────
_PII_PATTERNS: list[tuple[str, str]] = [
    ("email",       r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    ("us_ssn",      r"\b\d{3}-\d{2}-\d{4}\b"),
    ("us_phone",    r"\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b"),
    ("credit_card", r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
]

# ── High-entropy detection ────────────────────────────────────────────────────
_ENTROPY_MIN = 4.2
_ENTROPY_MIN_LEN = 20
_QUOTED_TOKEN_RE = re.compile(r'["\']([A-Za-z0-9+/=_\-]{20,})["\']')

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _redact_block(
    block: ContextBlock,
    redactions: list[RedactionRecord],
    redact_secrets: bool,
    redact_pii: bool,
    extra_patterns: list[dict],
) -> bool:
    """Mutates block.content in-place. Returns True if any redaction occurred."""
    text = block.content
    counter: dict[str, int] = {}
    changed = False

    def _placeholder(name: str) -> str:
        counter[name] = counter.get(name, 0) + 1
        return f"[REDACTED_{name.upper()}_{counter[name]}]"

    def _apply(text: str, pattern: str, name: str) -> str:
        nonlocal changed

        def _sub(m: re.Match) -> str:
            nonlocal changed
            ph = _placeholder(name)
            redactions.append(RedactionRecord(placeholder=ph, pattern_name=name))
            changed = True
            return ph

        return re.sub(pattern, _sub, text)

    if redact_secrets:
        for name, pattern in _SECRET_PATTERNS:
            text = _apply(text, pattern, name)

        # High-entropy tokens
        def _entropy_sub(m: re.Match) -> str:
            nonlocal changed
            token = m.group(1)
            if len(token) >= _ENTROPY_MIN_LEN and _entropy(token) >= _ENTROPY_MIN:
                ph = _placeholder("high_entropy_token")
                redactions.append(RedactionRecord(placeholder=ph, pattern_name="high_entropy_token"))
                changed = True
                return f'"{ph}"'
            return m.group(0)

        text = _QUOTED_TOKEN_RE.sub(_entropy_sub, text)

        # User-defined patterns
        for p in extra_patterns:
            if regex := p.get("regex"):
                text = _apply(text, regex, p.get("name", "custom"))

    if redact_pii:
        for name, pattern in _PII_PATTERNS:
            text = _apply(text, pattern, name)

    if changed:
        block.content = text
        block.contains_secrets = True

    return changed


def run(ctx: PipelineContext, config: PromptGuardConfig) -> PipelineContext:
    if ctx.blocked:
        return ctx

    for block in ctx.context_blocks:
        changed = _redact_block(
            block,
            ctx.redactions,
            config.redaction.secrets,
            config.redaction.pii,
            config.redaction.patterns,
        )
        if changed:
            block.sanitization_status = SanitizationStatus.redacted
            finding = Finding(
                rule_id="PP-REDACT-001",
                severity=Severity.info,
                message=f"Secrets/PII redacted from context block '{block.source}'.",
                decision=Decision.ALLOW_WITH_REDACTION,
                stage="redact",
            )
            block.findings.append(finding)
            ctx.all_findings.append(finding)

    return ctx


def restore(text: str, redactions: list[RedactionRecord]) -> str:
    """Reverse pass: restore placeholders in AI response (optional)."""
    # NOTE: This is intentionally a no-op in strict mode.
    # Enabling it means secrets briefly appear in the response object.
    # Kept here for completeness; the API can expose it as an option.
    return text
