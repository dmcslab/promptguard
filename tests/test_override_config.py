"""
Tests for per-workspace config overrides (TASK-091).

Covers:
- Override file discovery (.promptguard.override.yaml)
- PROMPTGUARD_OVERRIDE_URL (remote override)
- PROMPTGUARD_OVERRIDE_INLINE (inline YAML/JSON override)
- Deep merge semantics (scalars replace, lists append, dicts recurse)
- Safety invariants (fail_closed/block_on_critical cannot be weakened)
- Severity floor enforcement (override rules can't downgrade base rules)
- config_source tracking with override indicator
"""
from __future__ import annotations
import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from promptguard.config import (
    load_config,
    load_override_config,
    _deep_merge,
    _enforce_rule_severity_floor,
    _SEVERITY_ORDER,
)


# ── Deep merge ─────────────────────────────────────────────────────────────────

class TestDeepMerge:
    def test_scalar_override(self):
        base = {"version": 1, "max_prompt_tokens": 8000}
        override = {"max_prompt_tokens": 4000}
        result = _deep_merge(base, override)
        assert result["version"] == 1
        assert result["max_prompt_tokens"] == 4000

    def test_dict_merge(self):
        base = {"guardrails": {"security_policy": "base policy"}}
        override = {"guardrails": {"platform_config": "platform override"}}
        result = _deep_merge(base, override)
        assert result["guardrails"]["security_policy"] == "base policy"
        assert result["guardrails"]["platform_config"] == "platform override"

    def test_list_append(self):
        base = {"rules": [{"rule_id": "BASE-001"}]}
        override = {"rules": [{"rule_id": "OVER-001"}]}
        result = _deep_merge(base, override)
        assert len(result["rules"]) == 2
        assert result["rules"][0]["rule_id"] == "BASE-001"
        assert result["rules"][1]["rule_id"] == "OVER-001"

    def test_domains_append(self):
        base = {"allow_list": {"domains": ["api.anthropic.com"]}}
        override = {"allow_list": {"domains": ["internal.corp.com"]}}
        result = _deep_merge(base, override)
        assert "api.anthropic.com" in result["allow_list"]["domains"]
        assert "internal.corp.com" in result["allow_list"]["domains"]

    def test_new_key_added(self):
        base = {"version": 1}
        override = {"block_on_high": True}
        result = _deep_merge(base, override)
        assert result["block_on_high"] is True
        assert result["version"] == 1

    def test_nested_dict_recurse(self):
        base = {"audit": {"enabled": True, "log_path": "/var/log/pg.db"}}
        override = {"audit": {"log_path": "/tmp/pg.db"}}
        result = _deep_merge(base, override)
        assert result["audit"]["enabled"] is True
        assert result["audit"]["log_path"] == "/tmp/pg.db"


# ── Severity floor enforcement ─────────────────────────────────────────────────

class TestSeverityFloor:
    def test_override_downgrade_blocked(self):
        base_rules = [{"rule_id": "PP-INJ-001", "severity": "critical"}]
        merged_rules = [{"rule_id": "PP-INJ-001", "severity": "low"}]
        result = _enforce_rule_severity_floor(base_rules, merged_rules)
        assert result[0]["severity"] == "critical"

    def test_override_upgrade_allowed(self):
        base_rules = [{"rule_id": "PP-NET-001", "severity": "medium"}]
        merged_rules = [{"rule_id": "PP-NET-001", "severity": "critical"}]
        result = _enforce_rule_severity_floor(base_rules, merged_rules)
        assert result[0]["severity"] == "critical"

    def test_new_rule_not_affected(self):
        base_rules = [{"rule_id": "PP-INJ-001", "severity": "critical"}]
        merged_rules = [
            {"rule_id": "PP-INJ-001", "severity": "medium"},
            {"rule_id": "CUSTOM-001", "severity": "low"},
        ]
        result = _enforce_rule_severity_floor(base_rules, merged_rules)
        assert result[0]["severity"] == "critical"  # floor enforced
        assert result[1]["severity"] == "low"  # new rule, no floor

    def test_same_severity_ok(self):
        base_rules = [{"rule_id": "PP-INJ-001", "severity": "high"}]
        merged_rules = [{"rule_id": "PP-INJ-001", "severity": "high"}]
        result = _enforce_rule_severity_floor(base_rules, merged_rules)
        assert result[0]["severity"] == "high"


# ── Safety invariants ──────────────────────────────────────────────────────────

class TestSafetyInvariants:
    def test_cannot_disable_fail_closed(self, tmp_path, monkeypatch):
        """Override cannot set fail_closed=False when base has it True."""
        base = tmp_path / ".promptguard.yaml"
        base.write_text("version: 1\nfail_closed: true\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("PROMPTGUARD_CONFIG", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_INLINE", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_URL", raising=False)
        monkeypatch.delenv("PROMPTGUARD_OVERRIDE_URL", raising=False)
        monkeypatch.setenv("PROMPTGUARD_OVERRIDE_INLINE", json.dumps({"fail_closed": False}))

        with pytest.raises(ValueError, match="cannot set fail_closed=False"):
            load_config()

    def test_cannot_disable_block_on_critical(self, tmp_path, monkeypatch):
        """Override cannot set block_on_critical=False when base has it True."""
        base = tmp_path / ".promptguard.yaml"
        base.write_text("version: 1\nblock_on_critical: true\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("PROMPTGUARD_CONFIG", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_INLINE", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_URL", raising=False)
        monkeypatch.delenv("PROMPTGUARD_OVERRIDE_URL", raising=False)
        monkeypatch.setenv("PROMPTGUARD_OVERRIDE_INLINE", json.dumps({"block_on_critical": False}))

        with pytest.raises(ValueError, match="cannot set block_on_critical=False"):
            load_config()

    def test_can_strengthen_safety(self, tmp_path, monkeypatch):
        """Override CAN set fail_closed=True or block_on_critical=True."""
        base = tmp_path / ".promptguard.yaml"
        base.write_text("version: 1\nfail_closed: false\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("PROMPTGUARD_CONFIG", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_INLINE", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_URL", raising=False)
        monkeypatch.delenv("PROMPTGUARD_OVERRIDE_URL", raising=False)
        monkeypatch.setenv("PROMPTGUARD_OVERRIDE_INLINE", json.dumps({"fail_closed": True}))

        config = load_config()
        assert config.fail_closed is True


# ── Override discovery ──────────────────────────────────────────────────────────

class TestOverrideDiscovery:
    def test_override_file_discovered(self, tmp_path, monkeypatch):
        """CWD .promptguard.override.yaml is loaded and merged."""
        base = tmp_path / ".promptguard.yaml"
        base.write_text("version: 1\nmax_prompt_tokens: 8000\n")
        override = tmp_path / ".promptguard.override.yaml"
        override.write_text("max_prompt_tokens: 4000\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("PROMPTGUARD_CONFIG", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_INLINE", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_URL", raising=False)
        monkeypatch.delenv("PROMPTGUARD_OVERRIDE_URL", raising=False)
        monkeypatch.delenv("PROMPTGUARD_OVERRIDE_INLINE", raising=False)

        config = load_config()
        assert config.max_prompt_tokens == 4000
        assert "+override" in config._config_source

    def test_override_inline_env(self, tmp_path, monkeypatch):
        """PROMPTGUARD_OVERRIDE_INLINE is loaded and merged."""
        base = tmp_path / ".promptguard.yaml"
        base.write_text("version: 1\nmax_prompt_tokens: 8000\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("PROMPTGUARD_CONFIG", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_INLINE", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_URL", raising=False)
        monkeypatch.delenv("PROMPTGUARD_OVERRIDE_URL", raising=False)
        monkeypatch.setenv("PROMPTGUARD_OVERRIDE_INLINE", json.dumps({"max_prompt_tokens": 5000}))

        config = load_config()
        assert config.max_prompt_tokens == 5000
        assert "+override" in config._config_source

    def test_override_url_priority_over_file(self, tmp_path, monkeypatch):
        """PROMPTGUARD_OVERRIDE_URL takes priority over .promptguard.override.yaml."""
        base = tmp_path / ".promptguard.yaml"
        base.write_text("version: 1\nmax_prompt_tokens: 8000\n")
        override_file = tmp_path / ".promptguard.override.yaml"
        override_file.write_text("max_prompt_tokens: 9999\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("PROMPTGUARD_CONFIG", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_INLINE", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_URL", raising=False)
        monkeypatch.setenv("PROMPTGUARD_OVERRIDE_URL", "https://config.example.com/override.yaml")

        with patch("promptguard.config._fetch_remote_config") as mock_fetch:
            mock_fetch.return_value = {"max_prompt_tokens": 3000}
            config = load_config()
            assert config.max_prompt_tokens == 3000

    def test_no_override_uses_base(self, tmp_path, monkeypatch):
        """No override → base config is used as-is."""
        base = tmp_path / ".promptguard.yaml"
        base.write_text("version: 1\nmax_prompt_tokens: 8000\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("PROMPTGUARD_CONFIG", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_INLINE", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_URL", raising=False)
        monkeypatch.delenv("PROMPTGUARD_OVERRIDE_URL", raising=False)
        monkeypatch.delenv("PROMPTGUARD_OVERRIDE_INLINE", raising=False)

        config = load_config()
        assert config.max_prompt_tokens == 8000
        assert "+override" not in config._config_source

    def test_override_adds_rules(self, tmp_path, monkeypatch):
        """Override appends rules to base rules."""
        base = tmp_path / ".promptguard.yaml"
        base.write_text("version: 1\nrules: []\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("PROMPTGUARD_CONFIG", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_INLINE", raising=False)
        monkeypatch.delenv("PROMPTGUARD_CONFIG_URL", raising=False)
        monkeypatch.delenv("PROMPTGUARD_OVERRIDE_URL", raising=False)
        monkeypatch.setenv("PROMPTGUARD_OVERRIDE_INLINE", json.dumps({
            "rules": [
                {
                    "rule_id": "CUSTOM-001",
                    "name": "Custom Rule",
                    "severity": "high",
                    "pattern": "custom_pattern",
                    "message": "Custom warning",
                }
            ]
        }))

        config = load_config()
        # Should have default rules + custom rule
        rule_ids = [r.rule_id for r in config.rules]
        assert "CUSTOM-001" in rule_ids

    def test_load_override_config_returns_none_when_absent(self, tmp_path, monkeypatch):
        """load_override_config returns None when no override is found."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("PROMPTGUARD_OVERRIDE_URL", raising=False)
        monkeypatch.delenv("PROMPTGUARD_OVERRIDE_INLINE", raising=False)
        result = load_override_config()
        assert result is None