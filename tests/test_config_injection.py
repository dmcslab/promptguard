"""
Tests for PromptGuard config injection (TASK-090).

Covers:
- PROMPTGUARD_CONFIG_URL (remote config)
- PROMPTGUARD_CONFIG_INLINE (inline YAML/JSON)
- Priority order: config_path > URL > inline > PROMPTGUARD_CONFIG > CWD > home
- Error handling (bad URL, parse errors, size limits)
"""
from __future__ import annotations
import json
import os
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from promptguard.config import (
    load_config,
    _fetch_remote_config,
    _parse_inline_config,
    _MAX_YAML_SIZE,
)


# ── Inline config parsing ─────────────────────────────────────────────────────

class TestParseInlineConfig:
    def test_parse_valid_json(self):
        raw = json.dumps({"version": 1, "max_prompt_tokens": 4000})
        result = _parse_inline_config(raw)
        assert result["version"] == 1
        assert result["max_prompt_tokens"] == 4000

    def test_parse_valid_yaml(self):
        raw = "version: 1\nmax_prompt_tokens: 4000"
        result = _parse_inline_config(raw)
        assert result["version"] == 1
        assert result["max_prompt_tokens"] == 4000

    def test_parse_empty_string(self):
        result = _parse_inline_config("")
        assert result == {}

    def test_parse_whitespace_only(self):
        result = _parse_inline_config("   \n  ")
        assert result == {}

    def test_parse_invalid_raises(self):
        with pytest.raises(ValueError, match="Failed to parse"):
            _parse_inline_config("{{invalid yaml:::")

    def test_parse_json_with_rules(self):
        config = {
            "version": 1,
            "rules": [
                {
                    "rule_id": "TEST-001",
                    "name": "Test Rule",
                    "severity": "high",
                    "pattern": "test_pattern",
                    "message": "Test message",
                }
            ],
        }
        result = _parse_inline_config(json.dumps(config))
        assert len(result["rules"]) == 1
        assert result["rules"][0]["rule_id"] == "TEST-001"


# ── Remote config fetching ────────────────────────────────────────────────────

class TestFetchRemoteConfig:
    def test_rejects_non_http_url(self):
        with pytest.raises(ValueError, match="must be http"):
            _fetch_remote_config("ftp://example.com/config.yaml")

    def test_rejects_file_url(self):
        with pytest.raises(ValueError, match="must be http"):
            _fetch_remote_config("file:///etc/passwd")

    @patch("urllib.request.urlopen")
    def test_fetch_valid_yaml(self, mock_urlopen):
        yaml_body = b"version: 1\nmax_prompt_tokens: 6000"
        mock_resp = MagicMock()
        mock_resp.read.return_value = yaml_body
        mock_resp.headers = {"Content-Type": "application/yaml"}
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _fetch_remote_config("https://config.example.com/promptguard.yaml")
        assert result["version"] == 1
        assert result["max_prompt_tokens"] == 6000

    @patch("urllib.request.urlopen")
    def test_fetch_valid_json(self, mock_urlopen):
        json_body = json.dumps({"version": 1, "max_prompt_tokens": 5000}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = json_body
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _fetch_remote_config("https://config.example.com/promptguard.json")
        assert result["version"] == 1
        assert result["max_prompt_tokens"] == 5000

    @patch("urllib.request.urlopen")
    def test_fetch_too_large(self, mock_urlopen):
        big_body = b"x" * (_MAX_YAML_SIZE + 1)
        mock_resp = MagicMock()
        mock_resp.read.return_value = big_body
        mock_resp.headers = {"Content-Type": "application/yaml"}
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        with pytest.raises(ValueError, match="exceeds max size"):
            _fetch_remote_config("https://config.example.com/big.yaml")

    @patch("urllib.request.urlopen")
    def test_fetch_network_error(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        with pytest.raises(ValueError, match="Failed to fetch"):
            _fetch_remote_config("https://config.example.com/down.yaml")


# ── Priority order ─────────────────────────────────────────────────────────────

class TestConfigPriority:
    def test_inline_env_takes_precedence_over_local_file(self, tmp_path, monkeypatch):
        """PROMPTGUARD_CONFIG_INLINE should be used before local file discovery."""
        # Create a local config file
        local_config = tmp_path / ".promptguard.yaml"
        local_config.write_text("version: 1\nmax_prompt_tokens: 9999\n")

        # Set inline config with different value
        inline = json.dumps({"version": 1, "max_prompt_tokens": 3000})
        monkeypatch.setenv("PROMPTGUARD_CONFIG_INLINE", inline)
        monkeypatch.chdir(tmp_path)

        config = load_config()
        assert config.max_prompt_tokens == 3000
        assert config._config_source == "inline:env"

    def test_url_takes_precedence_over_inline(self, monkeypatch):
        """PROMPTGUARD_CONFIG_URL should be used before PROMPTGUARD_CONFIG_INLINE."""
        inline = json.dumps({"version": 1, "max_prompt_tokens": 3000})
        monkeypatch.setenv("PROMPTGUARD_CONFIG_INLINE", inline)

        with patch("promptguard.config._fetch_remote_config") as mock_fetch:
            mock_fetch.return_value = {"version": 1, "max_prompt_tokens": 7000}
            monkeypatch.setenv("PROMPTGUARD_CONFIG_URL", "https://config.example.com/pg.yaml")

            config = load_config()
            assert config.max_prompt_tokens == 7000
            assert "url:" in config._config_source

    def test_explicit_path_highest_priority(self, tmp_path, monkeypatch):
        """Explicit config_path arg takes precedence over everything."""
        explicit = tmp_path / "explicit.yaml"
        explicit.write_text("version: 1\nmax_prompt_tokens: 1234\n")

        monkeypatch.setenv("PROMPTGUARD_CONFIG_INLINE", json.dumps({"version": 1, "max_prompt_tokens": 5678}))
        monkeypatch.setenv("PROMPTGUARD_CONFIG_URL", "https://example.com/config.yaml")

        # Explicit path should win even with URL and inline set
        # (URL is only tried if config_path is None)
        config = load_config(config_path=str(explicit))
        assert config.max_prompt_tokens == 1234

    def test_config_file_env_var(self, tmp_path, monkeypatch):
        """PROMPTGUARD_CONFIG env var points to a local file."""
        config_file = tmp_path / "custom.yaml"
        config_file.write_text("version: 1\nmax_prompt_tokens: 4500\n")
        monkeypatch.setenv("PROMPTGUARD_CONFIG", str(config_file))

        config = load_config()
        assert config.max_prompt_tokens == 4500
        assert "file:" in config._config_source

    def test_cwd_default_discovery(self, tmp_path, monkeypatch):
        """Default discovery finds .promptguard.yaml in CWD."""
        local = tmp_path / ".promptguard.yaml"
        local.write_text("version: 1\nmax_prompt_tokens: 5500\n")
        monkeypatch.chdir(tmp_path)
        # Clear any env vars that might interfere
        monkeypatch.delenv("PROMPTGUARD_CONFIG", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_INLINE", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_URL", raising=False)

        config = load_config()
        assert config.max_prompt_tokens == 5500

    def test_no_config_uses_defaults(self, tmp_path, monkeypatch):
        """With no config file or env vars, load_config uses defaults."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        monkeypatch.chdir(empty_dir)
        monkeypatch.delenv("PROMPTGUARD_CONFIG", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_INLINE", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_URL", raising=False)

        config = load_config()
        assert config.version == 1
        assert config.max_prompt_tokens == 8000  # default
        assert len(config.rules) > 0  # default rules


# ── Config source tracking ────────────────────────────────────────────────────

class TestConfigSourceTracking:
    def test_inline_source_label(self, tmp_path, monkeypatch):
        inline = json.dumps({"version": 1, "max_prompt_tokens": 3000})
        monkeypatch.setenv("PROMPTGUARD_CONFIG_INLINE", inline)
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("PROMPTGUARD_CONFIG", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_URL", raising=False)

        config = load_config()
        assert config._config_source == "inline:env"

    def test_file_source_label(self, tmp_path, monkeypatch):
        local = tmp_path / ".promptguard.yaml"
        local.write_text("version: 1\nmax_prompt_tokens: 5500\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("PROMPTGUARD_CONFIG", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_INLINE", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_URL", raising=False)

        config = load_config()
        assert config._config_source.startswith("file:")