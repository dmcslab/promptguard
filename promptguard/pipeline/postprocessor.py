"""
Stage 8 — Response Postprocessor

Scans the AI response for dangerous patterns before surfacing
to the developer. Annotates with inline warnings. Does not block
by default — violations are appended as comment annotations.
"""
from __future__ import annotations
import re
from promptguard.models import Finding, Severity, Decision, PipelineContext
from promptguard.config import PromptGuardConfig

_RESPONSE_PATTERNS: list[tuple[str, str, Severity]] = [
    (r"shell\s*=\s*True",                    "PP-RESP-001: subprocess shell=True — command injection risk.", Severity.high),
    (r"pickle\.loads?",                       "PP-RESP-002: pickle.loads() — unsafe with untrusted data.", Severity.medium),
    (r"\beval\s*\(",                          "PP-RESP-003: eval() — code injection risk.", Severity.high),
    (r"\bexec\s*\(",                          "PP-RESP-004: exec() — code injection risk.", Severity.high),
    (r"innerHTML\s*=",                        "PP-RESP-005: innerHTML assignment — XSS risk.", Severity.medium),
    (r"document\.write\s*\(",                "PP-RESP-006: document.write() — XSS risk.", Severity.medium),
    (r"(?i)password\s*=\s*['\"][^'\"]{4,}",  "PP-RESP-007: Hardcoded password in response.", Severity.high),
    (r"\bmd5\s*\(",                           "PP-RESP-008: MD5 — not safe for passwords or integrity.", Severity.medium),
    (r"\bsha1\s*\(",                          "PP-RESP-009: SHA-1 — deprecated for security use.", Severity.medium),
    (r"verify\s*=\s*False",                  "PP-RESP-010: TLS verification disabled.", Severity.high),
    (r"ssl\._create_unverified_context",     "PP-RESP-011: SSL certificate verification disabled.", Severity.high),
    (r"0\.0\.0\.0",                           "PP-RESP-012: Binding to 0.0.0.0 — confirm intentional.", Severity.low),
    (r"(?i)git\s+(push|commit|merge)",        "PP-RESP-013: Git write operation suggested — human approval required.", Severity.high),
    (r"(?i)curl.*(-d|--data|--upload-file)",  "PP-RESP-014: curl with data upload — verify destination.", Severity.medium),
    (r"os\.system\s*\(",                      "PP-RESP-015: os.system() — prefer subprocess with list args.", Severity.medium),
    (r"subprocess\.call.*shell\s*=\s*True",  "PP-RESP-016: subprocess.call with shell=True.", Severity.high),
    (r"(?i)rm\s+-rf",                         "PP-RESP-017: Recursive delete — verify path before running.", Severity.high),
    (r"(?i)chmod\s+777",                      "PP-RESP-018: chmod 777 — overly permissive.", Severity.medium),
]


def _severity_to_icon(s: Severity) -> str:
    return {
        Severity.critical: "🔴",
        Severity.high:     "🟠",
        Severity.medium:   "🟡",
        Severity.low:      "🔵",
        Severity.info:     "⚪",
    }.get(s, "⚪")


def run(
    content: str,
    ctx: PipelineContext,
    config: PromptGuardConfig,
) -> tuple[str, list[Finding]]:
    """Returns (annotated_content, response_findings)."""
    findings: list[Finding] = []

    for pattern, message, severity in _RESPONSE_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(Finding(
                rule_id=message.split(":")[0],
                severity=severity,
                message=message,
                decision=Decision.ALLOW_WITH_REDACTION,
                stage="response",
            ))

    if findings:
        lines = [
            "",
            "<!-- PromptGuard Response Scan -->",
            "# ⚠ PromptGuard flagged the following in this response:",
        ]
        for f in findings:
            icon = _severity_to_icon(f.severity)
            lines.append(f"# {icon} [{f.severity.value.upper()}] {f.message}")
        lines.append("# Review carefully before using this code in production.")
        content += "\n" + "\n".join(lines)

    return content, findings
