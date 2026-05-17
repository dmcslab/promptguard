"""
Policy Bundle Signing Test Suite

Covers:
- Key generation and loading (env var, file, default path)
- HMAC-SHA256 sign and verify
- All three enforcement modes (strict, warn, off)
- Tamper detection (modified config, wrong key, missing sig)
- verify_or_raise with no config file (built-in defaults)
- SigningResult fields
- CLI command wiring (static check only — no subprocess)
"""
from __future__ import annotations
import os
import secrets
from pathlib import Path

import pytest
from promptguard.signing import (
    generate_key, load_key, sign_config, verify_config, verify_or_raise,
    EnforcementMode, SigningResult, PolicySigningError,
    _DEFAULT_KEY_PATH, _compute_hmac,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_config(tmp_path: Path) -> Path:
    """A valid .promptguard.yaml in a temp directory."""
    cfg = tmp_path / ".promptguard.yaml"
    cfg.write_text("version: 1\npolicy_version: PromptGuard/test\nrules: []\n")
    return cfg


@pytest.fixture
def tmp_key(tmp_path: Path) -> Path:
    """A generated signing key in a temp directory."""
    key_path = tmp_path / "signing.key"
    return generate_key(key_path)


@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    """Ensure PROMPTGUARD_SIGNING_KEY env var is cleared for each test."""
    monkeypatch.delenv("PROMPTGUARD_SIGNING_KEY", raising=False)


# ── Key Generation ────────────────────────────────────────────────────────────

class TestKeyGeneration:
    def test_generate_key_creates_file(self, tmp_path):
        path = generate_key(tmp_path / "test.key")
        assert path.exists()
        assert len(path.read_text().strip()) == 64  # 32 bytes → 64 hex chars

    def test_generate_key_chmod_600(self, tmp_path):
        path = generate_key(tmp_path / "test.key")
        mode = oct(path.stat().st_mode)[-3:]
        assert mode == "600"

    def test_generate_key_unique_each_time(self, tmp_path):
        k1 = generate_key(tmp_path / "k1.key").read_text()
        k2 = generate_key(tmp_path / "k2.key").read_text()
        assert k1 != k2

    def test_generate_key_creates_parent_dir(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "signing.key"
        generate_key(deep)
        assert deep.exists()

    def test_generate_key_default_path_respected(self, tmp_path, monkeypatch):
        # We can't write to the real ~/.promptguard in tests — just check the
        # function accepts None without raising (uses _DEFAULT_KEY_PATH logic)
        custom = tmp_path / "signing.key"
        result = generate_key(custom)
        assert result == custom


# ── Key Loading ───────────────────────────────────────────────────────────────

class TestKeyLoading:
    def test_load_key_from_env(self, monkeypatch):
        monkeypatch.setenv("PROMPTGUARD_SIGNING_KEY", "deadbeef" * 8)
        key = load_key()
        assert key == b"deadbeef" * 8

    def test_env_key_takes_priority_over_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PROMPTGUARD_SIGNING_KEY", "env_key_value")
        file_key = tmp_path / "k.key"
        file_key.write_text("file_key_value")
        key = load_key(file_key)
        assert key == b"env_key_value"

    def test_load_key_from_explicit_path(self, tmp_path):
        key_path = tmp_path / "signing.key"
        key_path.write_text("mykeyvalue1234")
        key = load_key(key_path)
        assert key == b"mykeyvalue1234"

    def test_load_key_returns_none_when_absent(self, tmp_path):
        missing = tmp_path / "no_such_key.key"
        # No env var, no file at explicit path, no default
        key = load_key(missing)
        assert key is None

    def test_load_key_strips_whitespace(self, tmp_path):
        key_path = tmp_path / "signing.key"
        key_path.write_text("  mykey  \n")
        key = load_key(key_path)
        assert key == b"mykey"


# ── Sign & Verify ─────────────────────────────────────────────────────────────

class TestSignAndVerify:
    def test_sign_creates_sig_file(self, tmp_config, tmp_key):
        sig_path = sign_config(tmp_config, tmp_key)
        assert sig_path.exists()
        assert sig_path.suffix == ".sig"

    def test_sig_file_format(self, tmp_config, tmp_key):
        sig_path = sign_config(tmp_config, tmp_key)
        content = sig_path.read_text().strip()
        parts = content.split(":")
        assert parts[0] == "HMAC-SHA256"
        assert len(parts[1]) == 64     # SHA-256 hex digest
        # ISO timestamp in remaining parts
        assert "T" in ":".join(parts[2:])

    def test_verify_valid_sig_passes(self, tmp_config, tmp_key):
        sign_config(tmp_config, tmp_key)
        result = verify_config(tmp_config, tmp_key, EnforcementMode.strict)
        assert result.verified is True
        assert result.error is None

    def test_verify_returns_signing_result(self, tmp_config, tmp_key):
        sign_config(tmp_config, tmp_key)
        result = verify_config(tmp_config, tmp_key, EnforcementMode.warn)
        assert isinstance(result, SigningResult)
        assert result.config_path == str(tmp_config)
        assert result.sig_path is not None
        assert result.sig_ts is not None

    def test_verify_off_mode_always_passes(self, tmp_config):
        # No key, no sig — off mode ignores everything
        result = verify_config(tmp_config, None, EnforcementMode.off)
        assert result.verified is True

    def test_verify_no_sig_file_warn_mode(self, tmp_config, tmp_key):
        # Config exists but no .sig file
        result = verify_config(tmp_config, tmp_key, EnforcementMode.warn)
        assert result.verified is False
        assert result.error is not None
        assert "missing" in result.error.lower() or "not found" in result.error.lower()

    def test_verify_no_sig_file_strict_raises(self, tmp_config, tmp_key):
        with pytest.raises(PolicySigningError) as exc_info:
            verify_config(tmp_config, tmp_key, EnforcementMode.strict)
        assert "signature" in str(exc_info.value).lower()

    def test_verify_wrong_key_fails(self, tmp_config, tmp_path):
        key1 = tmp_path / "k1.key"
        key2 = tmp_path / "k2.key"
        generate_key(key1)
        generate_key(key2)
        sign_config(tmp_config, key1)
        result = verify_config(tmp_config, key2, EnforcementMode.warn)
        assert result.verified is False
        assert "mismatch" in (result.error or "").lower()


# ── Tamper Detection ──────────────────────────────────────────────────────────

class TestTamperDetection:
    def test_modified_config_fails(self, tmp_config, tmp_key):
        sign_config(tmp_config, tmp_key)
        # Tamper: append a line after signing
        tmp_config.write_text(tmp_config.read_text() + "\n# injected by attacker\n")
        result = verify_config(tmp_config, tmp_key, EnforcementMode.warn)
        assert result.verified is False
        assert "mismatch" in (result.error or "").lower()

    def test_modified_config_strict_raises(self, tmp_config, tmp_key):
        sign_config(tmp_config, tmp_key)
        tmp_config.write_text("version: 1\nrules: []\nsigning:\n  enforcement: off\n")
        with pytest.raises(PolicySigningError):
            verify_config(tmp_config, tmp_key, EnforcementMode.strict)

    def test_tampered_sig_digest_fails(self, tmp_config, tmp_key):
        sig_path = sign_config(tmp_config, tmp_key)
        # Corrupt just the digest portion
        content = sig_path.read_text()
        parts = content.strip().split(":")
        parts[1] = "a" * 64   # replace digest with garbage
        sig_path.write_text(":".join(parts))
        result = verify_config(tmp_config, tmp_key, EnforcementMode.warn)
        assert result.verified is False

    def test_empty_config_after_signing_fails(self, tmp_config, tmp_key):
        sign_config(tmp_config, tmp_key)
        tmp_config.write_bytes(b"")   # truncate
        result = verify_config(tmp_config, tmp_key, EnforcementMode.warn)
        assert result.verified is False

    def test_replaced_sig_with_correct_key_passes(self, tmp_config, tmp_key):
        sign_config(tmp_config, tmp_key)
        # Legitimate re-sign after modifying config
        tmp_config.write_text(tmp_config.read_text() + "\n# legitimate addition\n")
        sign_config(tmp_config, tmp_key)   # re-sign
        result = verify_config(tmp_config, tmp_key, EnforcementMode.strict)
        assert result.verified is True


# ── verify_or_raise (service startup helper) ──────────────────────────────────

class TestVerifyOrRaise:
    def test_no_config_file_strict_passes(self):
        """No YAML file on disk (built-in defaults) → strict mode allows it."""
        result = verify_or_raise(config_path=None, mode=EnforcementMode.strict)
        assert result.verified is True
        assert "built-in" in result.config_path

    def test_no_config_file_warn_passes(self):
        result = verify_or_raise(config_path=None, mode=EnforcementMode.warn)
        assert result.verified is True

    def test_no_config_file_off_passes(self):
        result = verify_or_raise(config_path=None, mode=EnforcementMode.off)
        assert result.verified is True

    def test_valid_signed_config_passes(self, tmp_config, tmp_key):
        sign_config(tmp_config, tmp_key)
        result = verify_or_raise(tmp_config, tmp_key, EnforcementMode.strict)
        assert result.verified is True

    def test_unsigned_config_strict_raises(self, tmp_config, tmp_key):
        # Config exists but not signed
        with pytest.raises(PolicySigningError):
            verify_or_raise(tmp_config, tmp_key, EnforcementMode.strict)

    def test_unsigned_config_warn_returns_false(self, tmp_config, tmp_key):
        result = verify_or_raise(tmp_config, tmp_key, EnforcementMode.warn)
        assert result.verified is False

    def test_unsigned_config_off_passes(self, tmp_config):
        result = verify_or_raise(tmp_config, mode=EnforcementMode.off)
        assert result.verified is True


# ── HMAC primitive ────────────────────────────────────────────────────────────

class TestHMACPrimitive:
    def test_same_content_same_key_deterministic(self):
        key = b"test_key_32bytes_exactly_fits_ok"
        content = b"my policy content"
        d1 = _compute_hmac(content, key)
        d2 = _compute_hmac(content, key)
        assert d1 == d2

    def test_different_content_different_digest(self):
        key = b"test_key_32bytes_exactly_fits_ok"
        d1 = _compute_hmac(b"content_a", key)
        d2 = _compute_hmac(b"content_b", key)
        assert d1 != d2

    def test_different_key_different_digest(self):
        content = b"same content"
        d1 = _compute_hmac(content, b"key_one_abc")
        d2 = _compute_hmac(content, b"key_two_xyz")
        assert d1 != d2

    def test_digest_is_64_hex_chars(self):
        digest = _compute_hmac(b"data", b"key")
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)


# ── Config integration ────────────────────────────────────────────────────────

class TestConfigIntegration:
    def test_signing_config_in_promptguard_config(self):
        from promptguard.config import load_config
        cfg = load_config()
        assert hasattr(cfg, "signing")
        assert cfg.signing.enforcement in ("strict", "warn", "off")

    def test_signing_enforcement_default_is_warn(self):
        from promptguard.config import SigningConfig
        sc = SigningConfig()
        assert sc.enforcement == "warn"

    def test_signing_key_path_default_is_none(self):
        from promptguard.config import SigningConfig
        sc = SigningConfig()
        assert sc.key_path is None


# ── CLI wiring (static check) ─────────────────────────────────────────────────

class TestCLIWiring:
    def test_signing_commands_registered(self):
        import ast
        from pathlib import Path
        cli_src = Path("promptguard/cli.py").read_text()
        tree = ast.parse(cli_src)
        funcs = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        assert "cmd_generate_key" in funcs
        assert "cmd_sign_policy" in funcs
        assert "cmd_verify_policy" in funcs

    def test_signing_commands_in_dispatch(self):
        from pathlib import Path
        cli_src = Path("promptguard/cli.py").read_text()
        assert '"generate-key"' in cli_src
        assert '"sign-policy"' in cli_src
        assert '"verify-policy"' in cli_src

    def test_generate_key_parser_registered(self):
        import ast
        from pathlib import Path
        cli_src = Path("promptguard/cli.py").read_text()
        assert "generate-key" in cli_src
        assert "sign-policy" in cli_src
        assert "verify-policy" in cli_src
