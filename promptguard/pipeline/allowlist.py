"""
Stage 3 — Allow-List Validator

Checks all external URLs and MCP server references found in context
blocks against the configured allow-list. Non-allow-listed references
are quarantined or stripped from the block content.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse
from promptguard.models import (
    PipelineContext, ContextBlock, Finding, Severity,
    Decision, SanitizationStatus, TrustLevel,
)
from promptguard.config import PromptGuardConfig

_URL_RE = re.compile(
    r"https?://[a-zA-Z0-9.\-]+(:\d+)?(/[^\s\"'<>]*)?",
    re.IGNORECASE,
)


def _domain_allowed(url: str, allowed_domains: list[str]) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return any(
            host == d or host.endswith("." + d)
            for d in allowed_domains
        )
    except Exception:
        return False


def _strip_non_allowed_urls(
    content: str,
    allowed_domains: list[str],
) -> tuple[str, list[str]]:
    """Replace non-allow-listed URLs with [URL-QUARANTINED]. Returns (new_content, removed_urls)."""
    removed: list[str] = []

    def _replacer(m: re.Match) -> str:
        url = m.group(0)
        if _domain_allowed(url, allowed_domains):
            return url
        removed.append(url[:120])
        return "[URL-QUARANTINED]"

    new_content = _URL_RE.sub(_replacer, content)
    return new_content, removed


def run(ctx: PipelineContext, config: PromptGuardConfig) -> PipelineContext:
    if ctx.blocked:
        return ctx

    allowed_domains = config.allow_list.domains

    for block in ctx.context_blocks:
        if not block.contains_external_urls:
            continue

        # Only apply allow-list enforcement to lower-trust blocks
        if block.trust_level.priority < TrustLevel.SANITIZED_CONTEXT.priority:
            continue

        new_content, removed = _strip_non_allowed_urls(block.content, allowed_domains)

        if removed:
            block.content = new_content
            block.sanitization_status = SanitizationStatus.redacted
            finding = Finding(
                rule_id="PP-NET-ALLOWLIST",
                severity=Severity.medium,
                message=(
                    f"{len(removed)} non-allow-listed URL(s) stripped from context: "
                    + ", ".join(removed[:3])
                    + (" ..." if len(removed) > 3 else "")
                ),
                decision=Decision.ALLOW_WITH_REDACTION,
                stage="allowlist",
            )
            block.findings.append(finding)
            ctx.all_findings.append(finding)

    return ctx
