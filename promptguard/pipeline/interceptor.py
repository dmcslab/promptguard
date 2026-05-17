"""
Stage 1 — Intercept & Parse

- Token size guard
- Early prompt injection scan (fires before redaction)
- Language detection from file path
- Provider detection
"""
from __future__ import annotations
import re
from promptguard.models import (
    PipelineContext, Finding, Decision, Severity, TrustLevel, ContentType,
    SanitizationStatus, ContextBlock,
)
from promptguard.config import PromptGuardConfig

_TOKENS_PER_CHAR = 0.25   # ~4 chars per token
_MAX_PROMPT_LENGTH = 100_000  # Hard limit on prompt chars to prevent regex DoS


def _estimate_tokens(text: str) -> int:
    return int(len(text) * _TOKENS_PER_CHAR)


_EXT_MAP = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript", ".go": "go",
    ".rs": "rust", ".java": "java", ".kt": "kotlin",
    ".rb": "ruby", ".php": "php", ".cs": "csharp",
    ".cpp": "cpp", ".c": "c", ".sh": "bash",
    ".sql": "sql", ".yaml": "yaml", ".yml": "yaml",
    ".tf": "terraform", ".json": "json", ".md": "markdown",
}

# Ref: docs/JAILBREAK_REFERENCE.md — full pattern reference
# Patterns are pre-compiled at module load for performance and to enforce
# re.IGNORECASE | re.DOTALL consistently. Each entry is (compiled_pattern, rule_id, control_ref).
_PATTERN_DEFS: list[tuple[str, str, str]] = [
    # PP-INJ: Direct instruction override — docs/JAILBREAK_REFERENCE.md §2 §11.1
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|commands?|prompts?|rules?|context)", "PP-INJ-001", "SEC-AI-001 H-01"),
    (r"(?i)disregard\s+(security\s+)?(policy|guidelines|rules|controls)", "PP-INJ-002", "SEC-AI-001 H-02"),
    (r"(?i)override\s+system\s+prompt", "PP-INJ-003", "SEC-AI-001 H-03"),
    # PP-INJ-004: developer/god mode + standalone DAN/jailbreak/unrestricted
    # Ref: docs/JAILBREAK_REFERENCE.md §3 §11.2
    (r"(?i)(developer|god|unrestricted|jailbreak|DAN)\s+mode|\bDAN\b|\bjailbroken\b|\bunrestricted\b", "PP-INJ-004", "SEC-AI-001 H-04"),
    # PP-INJ-SYS: XML/bracket system-prompt override markers
    (r"(?i)<\s*/?system[a-z_]*\s*>|<\s*system-message\s*>|<\|system\|>|\[SYSTEM\]|###\s+System:", "PP-INJ-SYS", "SEC-AI-001 H-05"),
    (r"(?i)pretend\s+you\s+(are|have)\s+no\s+(restrictions|limits|rules)", "PP-INJ-PRETEND", "SEC-AI-001 H-06"),
    (r"(?i)(exfiltrate|upload\s+to|send\s+to\s+external)", "PP-INJ-006", "SEC-AI-001 H-07"),

    # PP-JB: Jailbreak persona assignment — docs/JAILBREAK_REFERENCE.md §3 §11.2
    (r"(?i)(act|behave|respond)\s+as\s+(a\s+)?(DAN|STAN|DUDE|AIM|OMEGA|ANR|BasedGPT|EvilBot|jailbroken\s+AI)", "PP-JB-001", "SEC-AI-001 H-04"),
    (r"(?i)(JAILBREAK|GODMODE)\s*[:\-]?\s*ENABLED", "PP-JB-002", "SEC-AI-001 H-04"),

    # PP-AUTH: Authority / PAP / consent coercion
    # Ref: docs/JAILBREAK_REFERENCE.md §5 §11.3
    (r"(?i)(as\s+a|this\s+is\s+a|I\s+am\s+a)\s+(licensed|certified|authorized|government|official|sanctioned)\s+\w+", "PP-AUTH-001", "SEC-AI-001 H-09"),
    (r"(?i)I\s+waive\s+(all\s+)?(safety|content|ethical)", "PP-AUTH-002", "SEC-AI-001 H-09"),

    # PP-LEAK: System prompt extraction — docs/JAILBREAK_REFERENCE.md §10 §11.4
    (r"(?i)(repeat|print|output|show|reveal)\s+(the\s+)?(system\s+prompt|initial\s+instructions?)", "PP-LEAK-001", "SEC-AI-001 H-11"),
    (r"(?i)complete\s+the\s+following\s*[:\-]?\s*['\"]?you\s+are\s+(a\s+)?helpful", "PP-LEAK-001", "SEC-AI-001 H-11"),

    # PP-OBFUSC: Encoding / obfuscation commands
    # Ref: docs/JAILBREAK_REFERENCE.md §7 §11.5
    (r"(?i)(base64|atob|btoa|fromBase64|decodeBase64)", "PP-OBFUSC-001", "SEC-AI-001 H-15"),

    # PP-IND: Indirect injection markers in code/documents
    # Ref: docs/JAILBREAK_REFERENCE.md §6 §11.6
    (r"(?i)(#|//|<!--|/\*)\s*(AI\s+(ASSISTANT|OVERRIDE|INSTRUCTION)|SYSTEM\s+OVERRIDE|LLM\s+INSTRUCTION)", "PP-IND-001", "SEC-AI-001 H-08"),
    (r"(?i)\[AI\s*:\s*(please|now|immediately)", "PP-IND-001", "SEC-AI-001 H-08"),
]

# Pre-compile all patterns at module load time for performance and to avoid
# re-compilation on every request. This also prevents regex DoS by validating
# patterns at import time rather than silently failing at runtime.
_COMPILED_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(pat, re.IGNORECASE | re.DOTALL), rid, ctrl)
    for pat, rid, ctrl in _PATTERN_DEFS
]


def run(ctx: PipelineContext, config: PromptGuardConfig) -> PipelineContext:
    prompt = ctx.raw_prompt.strip()

    # ── Hard length limit (regex DoS protection) ─────────────────────────────
    # Reject prompts longer than 100K chars to prevent catastrophic backtracking.
    # The token check below also catches most oversized inputs, but this hard
    # limit acts as a backstop for maliciously crafted adversarial inputs.
    if len(prompt) > _MAX_PROMPT_LENGTH:
        ctx.decision = Decision.BLOCK_SESSION
        ctx.block_reason = (
            f"Prompt exceeds maximum length ({len(prompt)} > {_MAX_PROMPT_LENGTH})."
        )
        return ctx

    # ── Token limit ──────────────────────────────────────────────────────────
    estimated = _estimate_tokens(prompt)
    if estimated > config.max_prompt_tokens:
        ctx.decision = Decision.BLOCK_SESSION
        ctx.block_reason = (
            f"Prompt exceeds token limit ({estimated} estimated > "
            f"{config.max_prompt_tokens} allowed). Split your request."
        )
        return ctx

    # ── Language from file path ──────────────────────────────────────────────
    if ctx.file_path and not ctx.language:
        import pathlib
        ctx.language = _EXT_MAP.get(pathlib.Path(ctx.file_path).suffix.lower())

    # ── Prompt injection scan (pre-compiled patterns) ────────────────────────
    for compiled, rule_id, control in _COMPILED_PATTERNS:
        if compiled.search(prompt):
            finding = Finding(
                rule_id=rule_id,
                severity=Severity.critical,
                message="Prompt injection attempt detected and blocked.",
                matched_control=control,
                matched_text=None,
                decision=Decision.BLOCK_SESSION,
                stage="intercept",
            )
            ctx.all_findings.append(finding)
            ctx.decision = Decision.BLOCK_SESSION
            ctx.block_reason = f"Prompt injection pattern [{rule_id}] detected."
            return ctx

    # ── Build developer task context block ───────────────────────────────────
    block = ContextBlock(
        source="developer_input",
        content_type=ContentType.developer_task,
        trust_level=TrustLevel.DEVELOPER_TASK,
        sanitization_status=SanitizationStatus.passed,
        content=prompt,
        original_hash=ContextBlock.make_hash(prompt),
        content_hash=ContextBlock.make_hash(prompt),
    )
    ctx.context_blocks.append(block)
    return ctx