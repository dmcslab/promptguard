"""Tests for the install-precommit CLI command and the generated hook script."""
from __future__ import annotations
import os
import stat
import subprocess
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from promptguard.cli import cmd_install_precommit, _PRECOMMIT_SCRIPT_TEMPLATE


class TestInstallPrecommit:
    """Tests for promptguard install-precommit."""

    def test_install_creates_hook_file(self, tmp_path):
        """install-precommit creates the hook script at the target path."""
        hook_dir = tmp_path / "hooks"
        args = type("Args", (), {"path": str(hook_dir), "force": False})()
        cmd_install_precommit(args)

        hook_path = hook_dir / "pre-commit"
        assert hook_path.exists()
        content = hook_path.read_text()
        assert "PromptGuard pre-commit hook" in content
        assert "git diff --cached" in content

    def test_hook_is_executable(self, tmp_path):
        """The installed hook must be executable."""
        hook_dir = tmp_path / "hooks"
        args = type("Args", (), {"path": str(hook_dir), "force": False})()
        cmd_install_precommit(args)

        hook_path = hook_dir / "pre-commit"
        mode = hook_path.stat().st_mode
        assert mode & stat.S_IXUSR
        assert mode & stat.S_IXGRP
        assert mode & stat.S_IXOTH

    def test_reinstall_own_hook_without_force(self, tmp_path):
        """Re-installing our own hook without --force should succeed (idempotent)."""
        hook_dir = tmp_path / "hooks"
        args = type("Args", (), {"path": str(hook_dir), "force": False})()
        cmd_install_precommit(args)
        # Should not raise
        cmd_install_precommit(args)

    def test_refuse_overwrite_foreign_hook(self, tmp_path):
        """Refuse to overwrite a pre-commit hook that is not ours without --force."""
        hook_dir = tmp_path / "hooks"
        hook_dir.mkdir()
        hook_path = hook_dir / "pre-commit"
        hook_path.write_text("#!/bin/sh\n# some other hook\nexit 0\n")

        args = type("Args", (), {"path": str(hook_dir), "force": False})()
        with pytest.raises(SystemExit) as exc_info:
            cmd_install_precommit(args)
        assert exc_info.value.code == 1

    def test_force_overwrite_foreign_hook(self, tmp_path):
        """--force should overwrite a foreign pre-commit hook."""
        hook_dir = tmp_path / "hooks"
        hook_dir.mkdir()
        hook_path = hook_dir / "pre-commit"
        hook_path.write_text("#!/bin/sh\n# some other hook\nexit 0\n")

        args = type("Args", (), {"path": str(hook_dir), "force": True})()
        cmd_install_precommit(args)

        content = hook_path.read_text()
        assert "PromptGuard pre-commit hook" in content

    def test_hook_contains_all_instruction_file_patterns(self):
        """The hook script must reference all known instruction file patterns."""
        required_patterns = [
            "CLAUDE.md",
            ".claude/CLAUDE.md",
            ".github/copilot-instructions.md",
            ".cursorrules",
            ".cursor/rules",
            ".cursor/rules.md",
            ".continuerc.json",
            ".continue/config.json",
            ".codeium/instructions.md",
            ".windsurf/rules.md",
            ".promptguard.yaml",
        ]
        for pattern in required_patterns:
            assert pattern in _PRECOMMIT_SCRIPT_TEMPLATE, f"Missing pattern: {pattern}"

    def test_hook_exit_codes_documented(self):
        """The hook must document exit codes 0, 1, 2."""
        assert "exit 0" in _PRECOMMIT_SCRIPT_TEMPLATE
        assert "exit 1" in _PRECOMMIT_SCRIPT_TEMPLATE
        assert "exit 2" in _PRECOMMIT_SCRIPT_TEMPLATE

    def test_hook_uses_validate_file(self):
        """The hook must call promptguard validate-file internally."""
        assert "promptguard validate-file" in _PRECOMMIT_SCRIPT_TEMPLATE

    def test_hook_checks_block_and_quarantine(self):
        """The hook must check for BLOCK_SESSION and QUARANTINE decisions."""
        assert "BLOCK_SESSION" in _PRECOMMIT_SCRIPT_TEMPLATE
        assert "QUARANTINE" in _PRECOMMIT_SCRIPT_TEMPLATE

    def test_hook_uses_git_diff_cached(self):
        """The hook must use git diff --cached to find staged files."""
        assert "git diff --cached --name-only --diff-filter=ACM" in _PRECOMMIT_SCRIPT_TEMPLATE


class TestPrecommitHookScript:
    """Integration tests for the generated pre-commit hook shell script."""

    def _write_hook(self, tmp_path):
        """Write the hook script to tmp_path and make it executable."""
        hook_path = tmp_path / "pre-commit"
        hook_path.write_text(_PRECOMMIT_SCRIPT_TEMPLATE)
        hook_path.chmod(0o755)
        return hook_path

    def test_no_staged_files_exits_0(self, tmp_path):
        """When no instruction files are staged, the hook should exit 0."""
        hook_path = self._write_hook(tmp_path)
        # Create a git repo with no staged instruction files
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=repo, capture_output=True)
        (repo / "README.md").write_text("hello")
        subprocess.run(["git", "add", "README.md"], cwd=repo, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True)

        # Stage a non-instruction file
        (repo / "main.py").write_text("print('hi')")
        subprocess.run(["git", "add", "main.py"], cwd=repo, capture_output=True)

        result = subprocess.run(
            ["sh", str(hook_path)],
            cwd=repo,
            capture_output=True,
            text=True,
            env={**os.environ, "PATH": os.environ["PATH"]},
        )
        assert result.returncode == 0

    def test_exits_0_when_no_staged_files(self, tmp_path):
        """Empty staging area should exit 0 immediately."""
        hook_path = self._write_hook(tmp_path)
        repo = tmp_path / "repo2"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=repo, capture_output=True)
        subprocess.run(["git", "commit", "--allow-empty", "-m", "init"], cwd=repo, capture_output=True)

        result = subprocess.run(
            ["sh", str(hook_path)],
            cwd=repo,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0

    def test_hook_detects_claude_md_pattern(self):
        """Verify CLAUDE.md is in the case statement."""
        assert "CLAUDE.md" in _PRECOMMIT_SCRIPT_TEMPLATE
        # Check it appears in the case/esac block
        lines = _PRECOMMIT_SCRIPT_TEMPLATE.splitlines()
        in_case = False
        case_content = []
        for line in lines:
            if "case" in line and "$file" in line:
                in_case = True
            if in_case:
                case_content.append(line)
            if in_case and line.strip() == "esac":
                in_case = False
        case_text = "\n".join(case_content)
        assert "CLAUDE.md" in case_text