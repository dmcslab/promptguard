"""Tests for wrapper.command_name config and CLI --name precedence."""
from __future__ import annotations
import argparse
import os
from pathlib import Path

import pytest
import yaml

from promptguard.config import load_config, WrapperConfig, PromptGuardConfig
from promptguard.cli import cmd_install_wrapper


class TestWrapperConfig:
    """Test WrapperConfig model and config loading."""

    def test_default_command_name(self):
        cfg = PromptGuardConfig()
        assert cfg.wrapper.command_name == "dmcslab-code"

    def test_explicit_command_name(self):
        cfg = PromptGuardConfig(wrapper=WrapperConfig(command_name="acme-code"))
        assert cfg.wrapper.command_name == "acme-code"

    def test_config_file_reads_command_name(self, tmp_path):
        config_data = {
            "version": 1,
            "wrapper": {"command_name": "myorg-cli"},
        }
        config_file = tmp_path / ".promptguard.yaml"
        config_file.write_text(yaml.dump(config_data))
        cfg = load_config(str(config_file))
        assert cfg.wrapper.command_name == "myorg-cli"

    def test_config_file_missing_wrapper_uses_default(self, tmp_path):
        config_data = {"version": 1}
        config_file = tmp_path / ".promptguard.yaml"
        config_file.write_text(yaml.dump(config_data))
        cfg = load_config(str(config_file))
        assert cfg.wrapper.command_name == "dmcslab-code"

    def test_config_file_empty_command_name_uses_default(self, tmp_path):
        config_data = {"version": 1, "wrapper": {"command_name": ""}}
        config_file = tmp_path / ".promptguard.yaml"
        config_file.write_text(yaml.dump(config_data))
        cfg = load_config(str(config_file))
        assert cfg.wrapper.command_name == "dmcslab-code"

    def test_config_file_null_command_name_uses_default(self, tmp_path):
        content = "version: 1\nwrapper:\n  command_name:\n"
        config_file = tmp_path / ".promptguard.yaml"
        config_file.write_text(content)
        cfg = load_config(str(config_file))
        assert cfg.wrapper.command_name == "dmcslab-code"


class TestInstallWrapperPrecedence:
    """Test CLI --name flag takes precedence over config."""

    def test_install_wrapper_with_config_name(self, tmp_path):
        """Install wrapper using config file command_name."""
        config_data = {"version": 1, "wrapper": {"command_name": "acme-code"}}
        config_file = tmp_path / ".promptguard.yaml"
        config_file.write_text(yaml.dump(config_data))
        install_dir = tmp_path / "bin"
        install_dir.mkdir()

        old_env = os.environ.get("PROMPTGUARD_CONFIG")
        os.environ["PROMPTGUARD_CONFIG"] = str(config_file)
        try:
            args = argparse.Namespace(name=None, path=str(install_dir))
            cmd_install_wrapper(args)

            wrapper_path = install_dir / "acme-code"
            assert wrapper_path.exists(), f"Wrapper not found at {wrapper_path}"
            content = wrapper_path.read_text()
            assert "acme-code" in content
        finally:
            if old_env is not None:
                os.environ["PROMPTGUARD_CONFIG"] = old_env
            else:
                os.environ.pop("PROMPTGUARD_CONFIG", None)

    def test_install_wrapper_default_no_config(self, tmp_path):
        """Install wrapper with no config and no --name → dmcslab-code."""
        install_dir = tmp_path / "bin"
        install_dir.mkdir()

        old_env = os.environ.pop("PROMPTGUARD_CONFIG", None)
        try:
            args = argparse.Namespace(name=None, path=str(install_dir))
            cmd_install_wrapper(args)

            wrapper_path = install_dir / "dmcslab-code"
            assert wrapper_path.exists(), f"Wrapper not found at {wrapper_path}"
            content = wrapper_path.read_text()
            assert "dmcslab-code" in content
        finally:
            if old_env is not None:
                os.environ["PROMPTGUARD_CONFIG"] = old_env

    def test_install_wrapper_cli_flag_wins(self, tmp_path):
        """--name flag should take precedence over config file."""
        config_data = {"version": 1, "wrapper": {"command_name": "config-name"}}
        config_file = tmp_path / ".promptguard.yaml"
        config_file.write_text(yaml.dump(config_data))
        install_dir = tmp_path / "bin"
        install_dir.mkdir()

        old_env = os.environ.get("PROMPTGUARD_CONFIG")
        os.environ["PROMPTGUARD_CONFIG"] = str(config_file)
        try:
            args = argparse.Namespace(name="cli-override", path=str(install_dir))
            cmd_install_wrapper(args)

            wrapper_path = install_dir / "cli-override"
            assert wrapper_path.exists(), f"Wrapper not found at {wrapper_path}"
            content = wrapper_path.read_text()
            assert "cli-override" in content
        finally:
            if old_env is not None:
                os.environ["PROMPTGUARD_CONFIG"] = old_env
            else:
                os.environ.pop("PROMPTGUARD_CONFIG", None)