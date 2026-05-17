"""
Stage 5 — Instruction File Validator

Validates provider instruction files (CLAUDE.md, copilot-instructions.md,
.cursorrules, etc.) for:
- Prompt injection and policy override attempts
- Embedded secrets / API keys
- Unauthorized git/network/system operations
- Conflicting or suspicious instructions

This stage runs both inline (when instruction file content is passed
with the request) and standalone (via the /validate/instruction-file
endpoint, called by the workspace guardian on file open/change).
"""
from __future__ import annotations

import re
import re
from promptguard.models import (
    PipelineContext, ContextBlock, TrustLevel, ContentType,
    SanitizationStatus, Finding, Severity, Decision,
)
from promptguard.providers_registry import AIProvider, get_spec
from promptguard.config import PromptGuardConfig

# ── Instruction-file-specific patterns ───────────────────────────────────────
_INSTR_PATTERNS: list[tuple[str, str, Severity, Decision, str]] = [
    # (regex, rule_id, severity, decision, message)
    (
        r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
        "PP-INSTR-INJ-001", Severity.critical, Decision.BLOCK_SESSION,
        "Instruction file contains prompt injection: override attempt.",
    ),
    (
        r"(?i)disregard\s+(security\s+)?(policy|guidelines|rules)",
        "PP-INSTR-INJ-002", Severity.critical, Decision.BLOCK_SESSION,
        "Instruction file attempts to disregard security policy.",
    ),
    (
        r"(?i)(always|must|should)\s+((?:commit|push|merge|deploy)(?:\s+(?:and|or|,)\s+(?:commit|push|merge|deploy))*\s+without)",
        "PP-INSTR-GIT-001", Severity.critical, Decision.BLOCK_SESSION,
        "Instruction file contains unauthorized auto-commit/push directive.",
    ),
    (
        r"(?i)(send|post|upload)\s+(to|data|secrets?)\s+(http|external|remote)",
        "PP-INSTR-EXF-001", Severity.critical, Decision.BLOCK_SESSION,
        "Instruction file contains data exfiltration directive.",
    ),
    (
        r"(?i)(disable|turn\s+off|bypass)\s+(security|monitoring|logging|scanning)",
        "PP-INSTR-SEC-001", Severity.high, Decision.QUARANTINE,
        "Instruction file attempts to disable security controls.",
    ),
    (
        r"(?i)(never|don.t|do\s+not)\s+(warn|flag|mention|report)",
        "PP-INSTR-SUPPRESS-001", Severity.high, Decision.QUARANTINE,
        "Instruction file suppresses warnings or security reporting.",
    ),
    (
        r"(?i)(curl|wget|fetch|http\.get)\s+https?://",
        "PP-INSTR-NET-001", Severity.medium, Decision.ALLOW_WITH_REDACTION,
        "Instruction file references external network calls.",
    ),
    (
        r"(?i)(rm\s+-rf|del\s+/f|format\s+c:)",
        "PP-INSTR-DESTR-001", Severity.critical, Decision.BLOCK_SESSION,
        "Instruction file contains destructive system command.",
    ),
    (
        r"(?i)(sudo|runas|privilege|admin)\s+(access|escalat|escalate)",
        "PP-INSTR-PRIV-001", Severity.high, Decision.QUARANTINE,
        "Instruction file requests privilege escalation.",
    ),
    (
        r"(?i)(base64|atob|btoa|fromCharCode)\s*[\(\[]",
        "PP-INSTR-OBFUSC-001", Severity.high, Decision.QUARANTINE,
        "Instruction file contains obfuscated/encoded payload.",
    ),
    (
        r"(?i)you\s+are\s+(now\s+)?(a\s+)?(DAN|jailbroken|unrestricted|unfiltered)",
        "PP-INSTR-JAILBREAK-001", Severity.critical, Decision.BLOCK_SESSION,
        "Instruction file contains jailbreak persona assignment.",
    ),
]

# Suspicious instruction length — very long instruction files warrant scrutiny
_SUSPICIOUS_LINE_COUNT = 500
_SUSPICIOUS_CHAR_COUNT = 30_000


def validate_instruction_file(
    content: str,
    file_path: str,
    provider: AIProvider,
    config: PromptGuardConfig,
) -> tuple[Decision, list[Finding], str]:
    """
    Standalone validator. Returns (decision, findings, sanitized_content).
    Called by workspace guardian and pipeline stage 5.
    """
    findings: list[Finding] = []
    worst_decision = Decision.ALLOW

    # ── Size heuristics ──────────────────────────────────────────────────────
    line_count = content.count("\n")
    if len(content) > _SUSPICIOUS_CHAR_COUNT or line_count > _SUSPICIOUS_LINE_COUNT:
        findings.append(Finding(
            rule_id="PP-INSTR-SIZE-001",
            severity=Severity.medium,
            message=(
                f"Instruction file is unusually large ({len(content)} chars, "
                f"{line_count} lines). Review for embedded payloads."
            ),
            decision=Decision.ALLOW_WITH_REDACTION,
            stage="instruction_file",
        ))
        worst_decision = _escalate(worst_decision, Decision.ALLOW_WITH_REDACTION)

    # ── Pattern scan ─────────────────────────────────────────────────────────
    for pattern, rule_id, severity, decision, message in _INSTR_PATTERNS:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            findings.append(Finding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                matched_text=match.group(0)[:80],
                decision=decision,
                stage="instruction_file",
            ))
            worst_decision = _escalate(worst_decision, decision)

    # ── Sanitize: strip lines that triggered QUARANTINE findings ────────────
    sanitized = _sanitize(content, findings)

    return worst_decision, findings, sanitized


def _escalate(current: Decision, new: Decision) -> Decision:
    """Return the more restrictive of two decisions."""
    order = [
        Decision.ALLOW,
        Decision.ALLOW_WITH_REDACTION,
        Decision.QUARANTINE,
        Decision.BLOCK_SESSION,
    ]
    return order[max(order.index(current), order.index(new))]


def _sanitize(content: str, findings: list[Finding]) -> str:
    """Remove or comment out lines that matched policy violations."""
    bad_texts = {
        f.matched_text for f in findings
        if f.matched_text and f.decision in (Decision.QUARANTINE, Decision.BLOCK_SESSION)
    }
    if not bad_texts:
        return content

    lines = content.splitlines()
    result = []
    for line in lines:
        if any(re.search(r'\b' + re.escape(bt) + r'\b', line, re.IGNORECASE) for bt in bad_texts if bt):
            result.append(f"# [PROMPTGUARD-REMOVED] {line}")
        else:
            result.append(line)
    return "\n".join(result)


def run(ctx: PipelineContext, config: PromptGuardConfig) -> PipelineContext:
    """
    Inline pipeline stage: validate the instruction_file_content
    passed with the request (if any).
    """
    if ctx.blocked or not ctx.instruction_file_path:
        return ctx

    # Find the instruction file block (added by workspace guardian or caller)
    instr_block = next(
        (b for b in ctx.context_blocks if b.content_type == ContentType.project_guidance),
        None,
    )
    if not instr_block:
        return ctx

    decision, findings, sanitized = validate_instruction_file(
        instr_block.content,
        ctx.instruction_file_path,
        ctx.provider,
        config,
    )

    instr_block.content = sanitized
    instr_block.findings.extend(findings)
    instr_block.policy_conflicts = [f.rule_id for f in findings]
    ctx.all_findings.extend(findings)

    if decision == Decision.BLOCK_SESSION:
        ctx.decision = Decision.BLOCK_SESSION
        ctx.block_reason = (
            f"Instruction file '{ctx.instruction_file_path}' contains "
            f"policy violations: "
            + ", ".join(f.rule_id for f in findings if f.decision == Decision.BLOCK_SESSION)
        )
        instr_block.sanitization_status = SanitizationStatus.blocked
    elif decision in (Decision.QUARANTINE, Decision.ALLOW_WITH_REDACTION):
        instr_block.sanitization_status = SanitizationStatus.redacted
        # Escalate overall decision if worse
        current_order = [Decision.ALLOW, Decision.ALLOW_WITH_REDACTION, Decision.QUARANTINE, Decision.BLOCK_SESSION]
        if current_order.index(decision) > current_order.index(ctx.decision):
            ctx.decision = decision

    return ctx
