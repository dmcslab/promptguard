"""
Stage 6 — Policy Engine

Runs the full rule set against every context block.
Produces a 4-way decision per finding:
  ALLOW | ALLOW_WITH_REDACTION | QUARANTINE | BLOCK_SESSION

The worst decision across all findings becomes the session decision.
"""
from __future__ import annotations
import re
from promptguard.models import (
    PipelineContext, ContextBlock, Finding,
    Severity, Decision, SanitizationStatus,
)
from promptguard.config import PromptGuardConfig, RuleConfig

_DECISION_ORDER = [
    Decision.ALLOW,
    Decision.ALLOW_WITH_REDACTION,
    Decision.QUARANTINE,
    Decision.BLOCK_SESSION,
]


def _escalate(current: Decision, candidate: Decision) -> Decision:
    return _DECISION_ORDER[max(
        _DECISION_ORDER.index(current),
        _DECISION_ORDER.index(candidate),
    )]


def _rule_applies(rule: RuleConfig, block: ContextBlock) -> bool:
    """Check whether a rule's applies_to list matches this block."""
    if "*" in rule.applies_to:
        return True
    return block.content_type.value in rule.applies_to


def _severity_to_decision(
    severity: str,
    default_decision: str,
    config: PromptGuardConfig,
) -> Decision:
    """
    Map rule severity + config thresholds to a Decision.
    Config can override: block_on_critical, block_on_high.
    """
    d = Decision(default_decision)
    sev = Severity(severity)
    if sev == Severity.critical and config.block_on_critical:
        return Decision.BLOCK_SESSION
    if sev == Severity.high and config.block_on_high:
        return Decision.BLOCK_SESSION
    return d


def run(ctx: PipelineContext, config: PromptGuardConfig) -> PipelineContext:
    if ctx.blocked:
        return ctx

    session_decision = Decision.ALLOW

    for block in ctx.context_blocks:
        block_worst = Decision.ALLOW

        for rule in config.rules:
            if not _rule_applies(rule, block):
                continue

            # Language filter
            if rule.languages and ctx.language and ctx.language not in rule.languages:
                continue

            try:
                match = re.search(rule.pattern, block.content, re.IGNORECASE)
            except re.error:
                continue

            if not match:
                continue

            sev = Severity(rule.severity)
            decision = _severity_to_decision(rule.severity, rule.default_decision, config)

            finding = Finding(
                rule_id=rule.rule_id,
                severity=sev,
                message=rule.message,
                matched_control=rule.matched_control,
                matched_text=match.group(0)[:120],
                decision=decision,
                stage="policy",
            )
            block.findings.append(finding)
            ctx.all_findings.append(finding)
            block_worst = _escalate(block_worst, decision)

        # Quarantine or block the block based on worst finding
        if block_worst == Decision.BLOCK_SESSION:
            block.sanitization_status = SanitizationStatus.blocked
            block.included = False
            block.exclusion_reason = "Policy: BLOCK_SESSION violation"
        elif block_worst == Decision.QUARANTINE:
            block.sanitization_status = SanitizationStatus.quarantined
            block.included = False
            block.exclusion_reason = "Policy: QUARANTINE — review required"
        elif block_worst == Decision.ALLOW_WITH_REDACTION:
            block.sanitization_status = SanitizationStatus.redacted

        session_decision = _escalate(session_decision, block_worst)

    # Apply session-level decision
    ctx.decision = _escalate(ctx.decision, session_decision)
    if ctx.decision == Decision.BLOCK_SESSION:
        error_findings = [f for f in ctx.all_findings if f.decision == Decision.BLOCK_SESSION]
        ctx.block_reason = (
            f"{len(error_findings)} critical policy violation(s): "
            + "; ".join(f"{f.rule_id}: {f.message[:60]}" for f in error_findings[:3])
        )

    return ctx
