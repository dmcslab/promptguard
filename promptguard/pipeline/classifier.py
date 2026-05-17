"""
Stage 2 — Context Classifier

Assigns TrustLevel, ContentType, and SanitizationStatus to every
ContextBlock. Also scans for risky file references and external URLs
within each block's content, setting metadata flags accordingly.
"""
from __future__ import annotations
import re
from promptguard.models import (
    PipelineContext, ContextBlock, TrustLevel, ContentType,
    SanitizationStatus, Finding, Severity, Decision,
)
from promptguard.config import PromptGuardConfig

# ── Risky file patterns (§8.3) ───────────────────────────────────────────────
_RISKY_FILE_PATTERNS = re.compile(
    r"""(?ix)
    \.env\b | \.env\.[a-z]+ |
    id_rsa | id_ed25519 | id_ecdsa |
    \.git.config | \.git-credentials |
    known_hosts | authorized_keys |
    \.npmrc | \.pypirc | settings\.xml |
    kubeconfig | \.kube/config |
    aws_credentials | \.aws/credentials |
    secrets\.ya?ml | application-prod\.ya?ml |
    azureProfile\.json |
    (?<![a-zA-Z])\.pem\b | (?<![a-zA-Z])\.key\b | (?<![a-zA-Z])\.pfx\b
    """,
    re.IGNORECASE,
)

_EXTERNAL_URL_PATTERN = re.compile(
    r"https?://(?!localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)"
    r"[a-zA-Z0-9.\-]+",
    re.IGNORECASE,
)

# ── Content type heuristics ───────────────────────────────────────────────────
_SOURCE_CODE_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs",
    ".java", ".kt", ".rb", ".php", ".cs", ".cpp", ".c",
    ".sh", ".bash", ".zsh",
}
_CONFIG_EXTS = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf"}
_DOC_EXTS    = {".md", ".rst", ".txt", ".adoc"}
_DEP_FILES   = {
    "requirements.txt", "pyproject.toml", "setup.py",
    "package.json", "Cargo.toml", "go.mod", "Gemfile", "pom.xml",
}


def _infer_content_type(source: str, existing: ContentType) -> ContentType:
    if existing != ContentType.unknown:
        return existing
    import pathlib
    p = pathlib.Path(source)
    name = p.name.lower()
    suffix = p.suffix.lower()
    if name in _DEP_FILES:
        return ContentType.dependency_manifest
    if suffix in _SOURCE_CODE_EXTS:
        return ContentType.source_code
    if suffix in _CONFIG_EXTS:
        return ContentType.configuration
    if suffix in _DOC_EXTS:
        return ContentType.documentation
    if "claude.md" in name or "copilot-instructions" in name or "cursorrules" in name:
        return ContentType.project_guidance
    return ContentType.unknown


def _infer_trust_level(source: str, content_type: ContentType, existing: TrustLevel) -> TrustLevel:
    """
    Re-confirm trust level based on source + content type.
    Classifier can only LOWER trust, never raise it.
    """
    # Tool output is always TOOL_OUTPUT trust level
    if source.startswith("tool:") or source.startswith("mcp:"):
        return TrustLevel.TOOL_OUTPUT
    # Repository content is lowest trust
    if content_type in (ContentType.source_code, ContentType.documentation,
                         ContentType.configuration, ContentType.build_log,
                         ContentType.test_output) and existing == TrustLevel.REPOSITORY_CONTENT:
        return TrustLevel.REPOSITORY_CONTENT
    return existing


def run(ctx: PipelineContext, config: PromptGuardConfig) -> PipelineContext:
    if ctx.blocked:
        return ctx

    for block in ctx.context_blocks:
        # Infer / confirm content type
        block.content_type = _infer_content_type(block.source, block.content_type)

        # Confirm trust level (can only lower, never raise)
        block.trust_level = _infer_trust_level(
            block.source, block.content_type, block.trust_level
        )

        # Scan for risky file references
        if _RISKY_FILE_PATTERNS.search(block.content):
            block.contains_risky_file_refs = True
            finding = Finding(
                rule_id="PP-FILE-001",
                severity=Severity.medium,
                message="Sensitive file reference detected in context block.",
                matched_control="SEC-AI-001 H-09",
                decision=Decision.ALLOW_WITH_REDACTION,
                stage="classify",
            )
            block.findings.append(finding)
            ctx.all_findings.append(finding)

        # Scan for external URLs
        if _EXTERNAL_URL_PATTERN.search(block.content):
            block.contains_external_urls = True
            # Only flag as finding in lower-trust blocks
            if block.trust_level.priority >= TrustLevel.SANITIZED_CONTEXT.priority:
                finding = Finding(
                    rule_id="PP-NET-001",
                    severity=Severity.medium,
                    message="External URL in lower-trust context block — validate against allow-list.",
                    decision=Decision.ALLOW_WITH_REDACTION,
                    stage="classify",
                )
                block.findings.append(finding)
                ctx.all_findings.append(finding)

    return ctx
