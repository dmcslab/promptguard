"""
PromptGuard — Core Type System

Implements the full data model from the Implementation Guide:
- 7-level instruction hierarchy / TrustLevel
- 4-way Decision model
- ContextBlock with trust metadata
- SafePromptEnvelope (7 structured sections)
- AuditEvent (Elastic-compatible)
"""
from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field
import hashlib
import uuid
from datetime import datetime, timezone


# ── Trust Levels (§4.1 Instruction Priority) ────────────────────────────────

class TrustLevel(str, Enum):
    SECURITY_POLICY        = "SECURITY_POLICY"           # Priority 1 — non-overridable
    PLATFORM_CONFIG        = "PLATFORM_CONFIG"           # Priority 2
    APPROVED_PROJECT       = "APPROVED_PROJECT"          # Priority 3 — validated instruction file
    DEVELOPER_TASK         = "DEVELOPER_TASK"            # Priority 4
    SANITIZED_CONTEXT      = "SANITIZED_CONTEXT"         # Priority 5
    TOOL_OUTPUT            = "TOOL_OUTPUT"               # Priority 6
    REPOSITORY_CONTENT     = "REPOSITORY_CONTENT"        # Priority 7 — lowest / untrusted

    @property
    def priority(self) -> int:
        return {
            "SECURITY_POLICY":    1,
            "PLATFORM_CONFIG":    2,
            "APPROVED_PROJECT":   3,
            "DEVELOPER_TASK":     4,
            "SANITIZED_CONTEXT":  5,
            "TOOL_OUTPUT":        6,
            "REPOSITORY_CONTENT": 7,
        }[self.value]


# ── Decision Model (§7.2 / §8.1) ────────────────────────────────────────────

class Decision(str, Enum):
    ALLOW                = "ALLOW"
    ALLOW_WITH_REDACTION = "ALLOW_WITH_REDACTION"
    QUARANTINE           = "QUARANTINE"
    BLOCK_SESSION        = "BLOCK_SESSION"


class Severity(str, Enum):
    critical = "critical"
    high     = "high"
    medium   = "medium"
    low      = "low"
    info     = "info"


# ── Findings ─────────────────────────────────────────────────────────────────

class Finding(BaseModel):
    rule_id: str
    severity: Severity
    message: str
    matched_control: str | None = None   # e.g. "SEC-AI-001 H-09"
    matched_text: str | None = None      # truncated, never raw secret
    decision: Decision
    stage: str


# ── Context Block (§18.1 Context Block Schema) ───────────────────────────────

class ContentType(str, Enum):
    source_code        = "source_code"
    project_guidance   = "project_guidance"    # CLAUDE.md, copilot-instructions.md etc.
    documentation      = "documentation"
    configuration      = "configuration"
    dependency_manifest= "dependency_manifest"
    build_log          = "build_log"
    test_output        = "test_output"
    tool_output        = "tool_output"
    mcp_response       = "mcp_response"
    developer_task     = "developer_task"
    unknown            = "unknown"


class SanitizationStatus(str, Enum):
    passed       = "passed"
    redacted     = "redacted"
    quarantined  = "quarantined"
    blocked      = "blocked"
    skipped      = "skipped"


class ContextBlock(BaseModel):
    source: str                                   # file path, "developer_input", "tool:X" etc.
    content_type: ContentType
    trust_level: TrustLevel
    sanitization_status: SanitizationStatus
    content: str                                  # sanitized content
    original_hash: str | None = None             # sha256 of original (before redaction)
    content_hash: str | None = None             # sha256 of sanitized content
    contains_secrets: bool = False
    contains_external_urls: bool = False
    contains_risky_file_refs: bool = False
    policy_conflicts: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    included: bool = True
    exclusion_reason: str | None = None

    @classmethod
    def make_hash(cls, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()


# ── Redaction Record ──────────────────────────────────────────────────────────

class RedactionRecord(BaseModel):
    placeholder: str
    pattern_name: str
    # NOTE: original value is never stored in models — only in ephemeral memory


# ── Provider Registry ─────────────────────────────────────────────────────────

class AIProvider(str, Enum):
    claude_code   = "claude_code"
    github_copilot= "github_copilot"
    continue_dev  = "continue_dev"
    cursor        = "cursor"
    codeium       = "codeium"
    generic       = "generic"


# ── Safe Prompt Envelope (§5.1) ───────────────────────────────────────────────

class EnvelopeSection(BaseModel):
    section_id: int
    title: str
    trust_level: TrustLevel
    content: str


class SafePromptEnvelope(BaseModel):
    """
    The structured output of the pipeline.
    7 ordered sections composed in strict priority order.
    """
    version: str = "1.0"
    envelope_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str | None = None
    user_id: str | None = None
    repository: str | None = None
    branch: str | None = None
    repo_root: str | None = None
    policy_version: str = "PromptGuard/v0.2"
    provider: AIProvider = AIProvider.generic
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # The 7 sections
    sections: list[EnvelopeSection] = Field(default_factory=list)

    # Summary metadata
    included_blocks: list[ContextBlock] = Field(default_factory=list)
    excluded_blocks: list[ContextBlock] = Field(default_factory=list)
    all_findings: list[Finding] = Field(default_factory=list)
    decision: Decision = Decision.ALLOW
    block_reason: str | None = None
    redaction_count: int = 0

    # Integrity
    envelope_hash: str | None = None

    def compute_hash(self) -> str:
        combined = "".join(s.content for s in self.sections)
        return hashlib.sha256(combined.encode()).hexdigest()

    def render(self) -> str:
        """Render the envelope as a structured prompt string."""
        lines = [
            f"SAFE_PROMPT_ENVELOPE_VERSION: {self.version}",
            f"SESSION:",
            f"  envelope_id: {self.envelope_id}",
            f"  provider: {self.provider.value}",
            f"  policy_version: {self.policy_version}",
            f"  timestamp: {self.timestamp}",
        ]
        if self.repository:
            lines.append(f"  repository: {self.repository}")
        if self.branch:
            lines.append(f"  branch: {self.branch}")
        if self.envelope_hash:
            lines.append(f"  envelope_hash: {self.envelope_hash}")
        lines.append("")

        for section in self.sections:
            lines += [
                f"[{section.section_id}. {section.title}]",
                section.content,
                "",
            ]

        return "\n".join(lines)


# ── Pipeline Context ──────────────────────────────────────────────────────────

class PipelineContext(BaseModel):
    """Mutable state carried through all 8 pipeline stages."""
    # Input
    raw_prompt: str
    file_path: str | None = None
    language: str | None = None
    provider: AIProvider = AIProvider.generic
    model: str | None = None
    extra_params: dict[str, Any] = Field(default_factory=dict)
    repo_root: str | None = None
    branch: str | None = None
    instruction_file_path: str | None = None   # CLAUDE.md / copilot-instructions.md etc.

    # Built during pipeline
    context_blocks: list[ContextBlock] = Field(default_factory=list)
    redactions: list[RedactionRecord] = Field(default_factory=list)
    all_findings: list[Finding] = Field(default_factory=list)
    decision: Decision = Decision.ALLOW
    block_reason: str | None = None
    envelope: SafePromptEnvelope | None = None

    # Convenience flag
    @property
    def blocked(self) -> bool:
        return self.decision == Decision.BLOCK_SESSION


# ── API Request/Response ──────────────────────────────────────────────────────

class ProxyRequest(BaseModel):
    prompt: str
    file_path: str | None = None
    language: str | None = None
    provider: str = "generic"
    repo_root: str | None = None
    branch: str | None = None
    instruction_file_content: str | None = None  # caller can pass CLAUDE.md text
    # MCP tool results to sanitize and include as TOOL_OUTPUT context blocks
    mcp_tool_results: list[dict[str, Any]] = Field(default_factory=list)
    extra_params: dict[str, Any] = Field(default_factory=dict)


class ViolationSummary(BaseModel):
    rule_id: str
    severity: str
    message: str
    decision: str
    stage: str


class InstructionFileRequest(BaseModel):
    """Validate an AI instruction file (CLAUDE.md, copilot-instructions.md, etc.)"""
    content: str = Field(max_length=100_000)
    file_path: str
    provider: str = "generic"
    repo_root: str | None = None


class InstructionFileResponse(BaseModel):
    decision: Decision
    findings: list[ViolationSummary] = Field(default_factory=list)
    sanitized_content: str | None = None
    provider: str
    file_path: str


class HealthResponse(BaseModel):
    status: str
    version: str
    rules_loaded: int
    providers_supported: list[str]
    signing_verified: bool = True
    signing_mode: str = "off"
    signing_error: str | None = None


class PreToolHookRequest(BaseModel):
    """Claude Code PreToolUse hook payload — validated input for /hook/pre-tool."""
    tool_name: str
    tool_input: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = None
    workspace_root: str | None = None

    model_config = {"extra": "forbid"}   # reject unknown fields
