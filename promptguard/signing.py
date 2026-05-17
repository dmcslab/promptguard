"""
Policy Bundle Signing — §9 / §17

Provides HMAC-SHA256 integrity verification for .promptguard.yaml.

Key storage priority (highest to lowest):
  1. PROMPTGUARD_SIGNING_KEY env var          (CI/CD, containers)
  2. ~/.promptguard/signing.key               (developer workstation)
  3. Path specified in config signing.key_path (custom)

The key is NEVER stored inside the repository.

Fail-closed behaviour:
  - If enforcement=strict and no key is found    → PolicySigningError
  - If enforcement=strict and signature mismatch → PolicySigningError
  - If enforcement=warn   and mismatch           → returns SigningResult with verified=False
  - If enforcement=off                           → signing skipped entirely

Signature file: <config_path>.sig
  Format: HMAC-SHA256:<hex_digest>:<iso_timestamp>
"""
from __future__ import annotations
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field


# ── Constants ─────────────────────────────────────────────────────────────────

_DEFAULT_KEY_PATH = Path.home() / ".promptguard" / "signing.key"
_SIG_PREFIX       = "HMAC-SHA256"
_KEY_BYTES        = 32   # 256-bit key

# ── Enforcement modes ─────────────────────────────────────────────────────────

class EnforcementMode(str, Enum):
    strict = "strict"   # fail closed — no valid sig = no service
    warn   = "warn"     # log warning, continue
    off    = "off"      # signing disabled


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class SigningResult:
    verified:    bool
    mode:        EnforcementMode
    config_path: str
    sig_path:    str | None  = None
    sig_ts:      str | None  = None   # timestamp embedded in sig file
    error:       str | None  = None   # human-readable reason if not verified


class PolicySigningError(RuntimeError):
    """Raised in strict mode when verification fails. Service must not start."""


# ── Key management ────────────────────────────────────────────────────────────

def generate_key(key_path: str | Path | None = None) -> Path:
    """
    Generate a new 256-bit random signing key and write it to disk.
    Returns the path it was written to.
    The key file is chmod 600 (owner read/write only).
    """
    path = Path(key_path) if key_path else _DEFAULT_KEY_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(_KEY_BYTES)
    path.write_text(key)
    path.chmod(0o600)
    return path


def load_key(key_path: str | Path | None = None) -> bytes | None:
    """
    Load the signing key. Returns None if not found (caller decides enforcement).
    Priority: env var → explicit path → default path.
    """
    # 1. Environment variable (highest priority)
    env_key = os.environ.get("PROMPTGUARD_SIGNING_KEY", "").strip()
    if env_key:
        return env_key.encode()

    # 2. Explicit path
    if key_path:
        p = Path(key_path)
        if p.exists():
            return p.read_text().strip().encode()

    # 3. Default path
    if _DEFAULT_KEY_PATH.exists():
        return _DEFAULT_KEY_PATH.read_text().strip().encode()

    return None


# ── Signing ───────────────────────────────────────────────────────────────────

def _compute_hmac(content: bytes, key: bytes) -> str:
    return hmac.new(key, content, hashlib.sha256).hexdigest()


def sign_config(
    config_path: str | Path,
    key_path: str | Path | None = None,
) -> Path:
    """
    Sign a policy config file. Writes a <config>.sig file alongside it.
    Returns the path to the signature file.
    """
    config_path = Path(config_path).resolve()
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    key = load_key(key_path)
    if key is None:
        raise PolicySigningError(
            "No signing key found. Run: promptguard generate-key\n"
            "Or set PROMPTGUARD_SIGNING_KEY environment variable."
        )

    content = config_path.read_bytes()
    digest = _compute_hmac(content, key)
    ts = datetime.now(timezone.utc).isoformat()

    sig_path = config_path.with_suffix(config_path.suffix + ".sig")
    sig_path.write_text(f"{_SIG_PREFIX}:{digest}:{ts}\n")
    sig_path.chmod(0o644)

    return sig_path


def verify_config(
    config_path: str | Path,
    key_path: str | Path | None = None,
    mode: EnforcementMode = EnforcementMode.strict,
) -> SigningResult:
    """
    Verify the signature of a policy config file.

    In strict mode: raises PolicySigningError on any failure.
    In warn mode:   returns SigningResult(verified=False) with error message.
    In off mode:    returns SigningResult(verified=True) immediately.
    """
    config_path = Path(config_path).resolve()
    sig_path = config_path.with_suffix(config_path.suffix + ".sig")

    # Off mode — skip entirely
    if mode == EnforcementMode.off:
        return SigningResult(
            verified=True,
            mode=mode,
            config_path=str(config_path),
        )

    def _fail(reason: str) -> SigningResult:
        result = SigningResult(
            verified=False,
            mode=mode,
            config_path=str(config_path),
            sig_path=str(sig_path) if sig_path.exists() else None,
            error=reason,
        )
        if mode == EnforcementMode.strict:
            raise PolicySigningError(
                f"Policy bundle signature verification FAILED — service will not start.\n"
                f"Reason: {reason}\n"
                f"Config: {config_path}\n"
                f"Run: promptguard sign-policy --config {config_path}"
            )
        return result

    # Config file must exist
    if not config_path.exists():
        return _fail(f"Config file not found: {config_path}")

    # Signature file must exist
    if not sig_path.exists():
        return _fail(
            f"Signature file missing: {sig_path}\n"
            f"  The policy has not been signed. Run:\n"
            f"  promptguard sign-policy --config {config_path}"
        )

    # Key must be available
    key = load_key(key_path)
    if key is None:
        return _fail(
            "Signing key not found. Set PROMPTGUARD_SIGNING_KEY or run:\n"
            "  promptguard generate-key"
        )

    # Parse signature file
    sig_content = sig_path.read_text().strip()
    parts = sig_content.split(":")
    if len(parts) < 3 or parts[0] != _SIG_PREFIX:
        return _fail(f"Signature file format invalid: {sig_path}")

    stored_digest = parts[1]
    stored_ts     = ":".join(parts[2:])   # ISO timestamp may contain colons

    # Recompute HMAC over current file content
    content = config_path.read_bytes()
    expected_digest = _compute_hmac(content, key)

    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(expected_digest, stored_digest):
        return _fail(
            "HMAC digest mismatch — policy file has been modified since signing.\n"
            f"  Re-sign with: promptguard sign-policy --config {config_path}"
        )

    return SigningResult(
        verified=True,
        mode=mode,
        config_path=str(config_path),
        sig_path=str(sig_path),
        sig_ts=stored_ts,
    )


# ── Convenience: verify-or-raise used by service startup ─────────────────────

def verify_or_raise(
    config_path: str | Path | None,
    key_path: str | Path | None = None,
    mode: EnforcementMode = EnforcementMode.strict,
) -> SigningResult:
    """
    Called during service startup. config_path=None means built-in defaults
    were used (no YAML file on disk) — skip verification unless strict mode
    explicitly requires a signed config.
    """
    if config_path is None:
        # No config file on disk — using built-in defaults
        if mode == EnforcementMode.strict:
            # Strict mode with no config file: acceptable — defaults are trusted
            return SigningResult(
                verified=True,
                mode=mode,
                config_path="<built-in defaults>",
                error=None,
            )
        return SigningResult(
            verified=True,
            mode=mode,
            config_path="<built-in defaults>",
        )

    return verify_config(config_path, key_path, mode)
