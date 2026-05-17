"""
Stage 7 — Safe Prompt Envelope Builder

Composes the 7-section structured output in strict priority order:

  1. SECURITY_POLICY         — non-overridable, always first
  2. PLATFORM_CONFIGURATION  — org/env config
  3. APPROVED_PROJECT_GUIDANCE — sanitized instruction file
  4. DEVELOPER_TASK          — sanitized prompt
  5. SANITIZED_CONTEXT       — included + redacted blocks
  6. QUARANTINE_SUMMARY      — what was excluded and why
  7. SECURITY_FOOTER         — final reminder

Each section maps to a TrustLevel. Lower sections cannot override higher.
"""
from __future__ import annotations
from promptguard.models import (
    PipelineContext, SafePromptEnvelope, EnvelopeSection,
    TrustLevel, ContentType, Decision,
)
from promptguard.config import PromptGuardConfig

_LANGUAGE_GUARDRAILS: dict[str, str] = {
    "python": (
        "Use type hints. Prefer pathlib. Never shell=True with subprocess. "
        "Use parameterized queries for SQL. Never unpickle untrusted data."
    ),
    "javascript": (
        "Avoid innerHTML; use textContent or DOMPurify. Never eval() or Function(). "
        "Validate all DOM inputs. Use const/let, never var."
    ),
    "typescript": (
        "Use strict types; avoid any. Validate external data with zod or io-ts. "
        "No innerHTML; use DOMPurify. Never disable strictNullChecks."
    ),
    "go":   "Check all errors. Use crypto/rand not math/rand. No exec with shell expansion.",
    "java": "Use PreparedStatement always. Validate with Bean Validation. No reflection without need.",
    "bash": "Quote all variables. set -euo pipefail. Validate inputs before external commands.",
    "sql":  "Parameterized queries only. No string concatenation. LIMIT all SELECTs.",
    "rust": "Prefer safe Rust. Document every unsafe block. Validate all external input.",
    "terraform": "Never hardcode creds. Least-privilege IAM. Enable state encryption. Tag all resources.",
}


def run(ctx: PipelineContext, config: PromptGuardConfig) -> PipelineContext:
    if ctx.decision == Decision.BLOCK_SESSION:
        return ctx  # No envelope for blocked sessions

    sections: list[EnvelopeSection] = []

    # ── Section 1: Security Policy ───────────────────────────────────────────
    sec_policy_text = config.guardrails.security_policy.strip()
    if ctx.language and (lang_guardrail := _LANGUAGE_GUARDRAILS.get(ctx.language)):
        sec_policy_text += f"\n\n[{ctx.language.upper()} SPECIFIC]\n{lang_guardrail}"

    sections.append(EnvelopeSection(
        section_id=1,
        title="SECURITY_POLICY",
        trust_level=TrustLevel.SECURITY_POLICY,
        content=sec_policy_text,
    ))

    # ── Section 2: Platform Configuration ───────────────────────────────────
    platform_parts = []
    if config.guardrails.platform_config:
        platform_parts.append(config.guardrails.platform_config.strip())
    if ctx.repo_root:
        platform_parts.append(f"Authorized workspace root: {ctx.repo_root}")
    if ctx.branch:
        platform_parts.append(f"Authorized branch: {ctx.branch}")
    platform_parts.append(f"Provider: {ctx.provider.value}")
    platform_parts.append(f"Policy version: {config.policy_version}")

    sections.append(EnvelopeSection(
        section_id=2,
        title="PLATFORM_CONFIGURATION",
        trust_level=TrustLevel.PLATFORM_CONFIG,
        content="\n".join(platform_parts),
    ))

    # ── Section 3: Approved Project Guidance ─────────────────────────────────
    guidance_blocks = [
        b for b in ctx.context_blocks
        if b.content_type == ContentType.project_guidance and b.included
    ]
    if guidance_blocks:
        guidance_text = "\n\n---\n\n".join(
            f"[Source: {b.source}]\n{b.content}" for b in guidance_blocks
        )
    else:
        guidance_text = "(No validated project guidance file found for this workspace.)"

    sections.append(EnvelopeSection(
        section_id=3,
        title="APPROVED_PROJECT_GUIDANCE",
        trust_level=TrustLevel.APPROVED_PROJECT,
        content=guidance_text,
    ))

    # ── Section 4: Developer Task ─────────────────────────────────────────────
    task_blocks = [
        b for b in ctx.context_blocks
        if b.content_type == ContentType.developer_task and b.included
    ]
    task_text = (
        "\n\n".join(b.content for b in task_blocks)
        if task_blocks else ctx.raw_prompt
    )
    if ctx.file_path:
        task_text = f"[File context: {ctx.file_path}]\n\n{task_text}"

    sections.append(EnvelopeSection(
        section_id=4,
        title="DEVELOPER_TASK",
        trust_level=TrustLevel.DEVELOPER_TASK,
        content=task_text,
    ))

    # ── Section 5: Sanitized Context ─────────────────────────────────────────
    context_blocks = [
        b for b in ctx.context_blocks
        if b.content_type not in (ContentType.project_guidance, ContentType.developer_task)
        and b.included
    ]
    if context_blocks:
        context_parts = []
        for b in context_blocks:
            meta = (
                f"[source={b.source} | trust={b.trust_level.value} | "
                f"type={b.content_type.value} | status={b.sanitization_status.value}]"
            )
            context_parts.append(f"{meta}\n{b.content}")
        context_text = "\n\n".join(context_parts)
    else:
        context_text = "(No additional context blocks.)"

    sections.append(EnvelopeSection(
        section_id=5,
        title="SANITIZED_CONTEXT",
        trust_level=TrustLevel.SANITIZED_CONTEXT,
        content=context_text,
    ))

    # ── Section 6: Quarantine Summary ─────────────────────────────────────────
    excluded_blocks = [b for b in ctx.context_blocks if not b.included]
    if excluded_blocks:
        quarantine_lines = [
            f"The following {len(excluded_blocks)} context block(s) were excluded:",
        ]
        for b in excluded_blocks:
            quarantine_lines.append(
                f"  - [{b.source}] {b.content_type.value}: {b.exclusion_reason}"
            )
        quarantine_text = "\n".join(quarantine_lines)
    else:
        quarantine_text = "(No context was quarantined.)"

    sections.append(EnvelopeSection(
        section_id=6,
        title="QUARANTINE_SUMMARY",
        trust_level=TrustLevel.TOOL_OUTPUT,
        content=quarantine_text,
    ))

    # ── Section 7: Security Footer ────────────────────────────────────────────
    sections.append(EnvelopeSection(
        section_id=7,
        title="SECURITY_FOOTER",
        trust_level=TrustLevel.SECURITY_POLICY,
        content=config.guardrails.security_footer.strip(),
    ))

    # ── Assemble envelope ─────────────────────────────────────────────────────
    envelope = SafePromptEnvelope(
        provider=ctx.provider,
        repo_root=ctx.repo_root,
        branch=ctx.branch,
        policy_version=config.policy_version,
        sections=sections,
        included_blocks=[b for b in ctx.context_blocks if b.included],
        excluded_blocks=excluded_blocks,
        all_findings=ctx.all_findings,
        decision=ctx.decision,
        block_reason=ctx.block_reason,
        redaction_count=len(ctx.redactions),
    )
    envelope.envelope_hash = envelope.compute_hash()
    ctx.envelope = envelope
    return ctx
