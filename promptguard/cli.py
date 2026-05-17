#!/usr/bin/env python3
"""
promptguard CLI

  promptguard serve           Start the local proxy service
  promptguard validate        Validate a config file
  promptguard validate-file   Validate an instruction file (CLAUDE.md etc.)
  promptguard scan-workspace  Scan all provider instruction files in a dir
  promptguard install-hooks   Write Claude Code PreToolUse hooks
  promptguard install-precommit  Install git pre-commit hook
  promptguard install-wrapper Install CLI wrapper script
  promptguard audit stats     Show audit statistics
  promptguard audit prune     Delete old audit records
  promptguard test-prompt     Dry-run a prompt through the pipeline
"""
from __future__ import annotations
import argparse
import json
import stat
import sys
from pathlib import Path


def cmd_generate_key(args):
    """Generate a new 256-bit signing key at the default or specified path."""
    from promptguard.signing import generate_key, _DEFAULT_KEY_PATH
    path = Path(args.key_path) if args.key_path else None
    written = generate_key(path)
    print(f"✅  Signing key generated: {written}")
    print(f"   Keep this file OUTSIDE the repository.")
    print(f"   To use in CI/CD: export PROMPTGUARD_SIGNING_KEY=$(cat {written})")
    print(f"   To sign your config:  promptguard sign-policy --config .promptguard.yaml")


def cmd_sign_policy(args):
    """Sign a policy config file — writes a .sig alongside it."""
    from promptguard.signing import sign_config, PolicySigningError
    try:
        sig_path = sign_config(args.config, args.key_path or None)
        config_path = Path(args.config).resolve()
        print(f"✅  Policy signed:")
        print(f"   Config : {config_path}")
        print(f"   Sig    : {sig_path}")
        print(f"   Add {sig_path.name} to version control (it contains no secrets).")
        print(f"   Add {sig_path.stem.replace('.promptguard', '')}.key to .gitignore.")
    except FileNotFoundError as e:
        print(f"❌  {e}", file=sys.stderr)
        sys.exit(1)
    except PolicySigningError as e:
        print(f"❌  {e}", file=sys.stderr)
        sys.exit(1)


def cmd_verify_policy(args):
    """Verify the signature of a policy config file."""
    from promptguard.signing import verify_config, EnforcementMode, PolicySigningError
    mode = EnforcementMode(args.mode)
    try:
        result = verify_config(args.config, args.key_path or None, mode)
        if result.verified:
            print(f"✅  Signature valid")
            print(f"   Config  : {result.config_path}")
            print(f"   Sig     : {result.sig_path}")
            print(f"   Signed  : {result.sig_ts}")
            print(f"   Mode    : {result.mode.value}")
        else:
            print(f"⚠   Signature INVALID: {result.error}", file=sys.stderr)
            sys.exit(1)
    except PolicySigningError as e:
        print(f"🔴  FAILED (strict mode): {e}", file=sys.stderr)
        sys.exit(2)


def cmd_serve(args):
    import uvicorn, os
    if args.config:
        os.environ["PROMPTGUARD_CONFIG"] = args.config
    uvicorn.run(
        "promptguard.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


def cmd_validate(args):
    from promptguard.config import load_config
    try:
        cfg = load_config(args.config)
        print(f"✅  Config valid — {len(cfg.rules)} rules loaded")
        for r in cfg.rules:
            sev = r.severity.upper()
            print(f"   [{sev:8}] {r.rule_id}: {r.message[:60]}")
    except Exception as e:
        print(f"❌  Config invalid: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_validate_file(args):
    from promptguard.config import load_config
    from promptguard.pipeline.instr_validator import validate_instruction_file
    from promptguard.providers_registry import provider_from_string

    cfg = load_config()
    path = Path(args.file)
    if not path.exists():
        print(f"❌  File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    content = path.read_text(errors="replace")
    provider = provider_from_string(args.provider or "generic")
    decision, findings, sanitized = validate_instruction_file(content, str(path), provider, cfg)

    icon = {"ALLOW": "✅", "ALLOW_WITH_REDACTION": "🟡", "QUARANTINE": "🟠", "BLOCK_SESSION": "🔴"}
    print(f"\n{icon.get(decision.value, '?')} Decision: {decision.value}")
    print(f"File    : {path}")
    print(f"Provider: {provider.value}")
    if findings:
        print(f"\nFindings ({len(findings)}):")
        for f in findings:
            print(f"  [{f.severity.value.upper():8}] {f.rule_id}: {f.message}")
    else:
        print("No findings.")

    if args.output and decision.value != "BLOCK_SESSION":
        Path(args.output).write_text(sanitized)
        print(f"\nSanitized content written to: {args.output}")


def cmd_scan_workspace(args):
    from promptguard.config import load_config
    from promptguard.pipeline.instr_validator import validate_instruction_file
    from promptguard.providers_registry import get_instruction_files, detect_provider

    cfg = load_config()
    root = Path(args.workspace or ".")
    files = get_instruction_files(root)

    if not files:
        print(f"No AI provider instruction files found in: {root}")
        return

    detected = detect_provider(root)
    print(f"\n🔍  Detected providers: {', '.join(p.value for p in detected)}")
    print(f"📁  Workspace: {root}\n")

    for provider, path in files:
        content = path.read_text(errors="replace")
        decision, findings, _ = validate_instruction_file(content, str(path), provider, cfg)
        icon = {"ALLOW": "✅", "ALLOW_WITH_REDACTION": "🟡", "QUARANTINE": "🟠", "BLOCK_SESSION": "🔴"}
        print(f"{icon.get(decision.value, '?')}  [{provider.value:16}] {path.relative_to(root)}  →  {decision.value}")
        for f in findings:
            print(f"     [{f.severity.value.upper():8}] {f.rule_id}: {f.message[:70]}")


def cmd_install_wrapper(args):
    """Install the PromptGuard CLI wrapper script."""
    from promptguard.config import _validate_command_name
    # Precedence: CLI flag > config file > default
    if args.name is not None:
        # Explicit --name flag provided (even if it's "dmcslab-code")
        name = args.name
    else:
        name = None
    if name is None:
        from promptguard.config import load_config
        cfg = load_config()
        name = cfg.wrapper.command_name
    # Validate name against path traversal
    _validate_command_name(name)
    install_path = Path(args.path or "/usr/local/bin") / name

    script = _WRAPPER_SCRIPT_TEMPLATE.replace("{{WRAPPER_NAME}}", name)

    # Check if target exists and is not ours
    if install_path.exists():
        existing = install_path.read_text()
        if f"PromptGuard wrapper {name}" not in existing:
            print(f"⚠   {install_path} already exists and is not a PromptGuard wrapper.")
            print(f"    Remove it first, or choose a different --name.")
            sys.exit(1)

    install_path.parent.mkdir(parents=True, exist_ok=True)
    install_path.write_text(script)
    install_path.chmod(0o755)
    print(f"✅  {name} installed to: {install_path}")
    print(f"    Run `{name}` instead of `claude` for validated execution.")


def cmd_install_precommit(args):
    """Install a git pre-commit hook that validates AI instruction files."""
    # Determine target path
    if args.path:
        hook_dir = Path(args.path)
    else:
        # Auto-detect .git/hooks from CWD
        git_dir = Path(".git")
        if git_dir.is_file():
            # .git file (worktree) — read the gitdir
            git_dir = Path(git_dir.read_text().strip().splitlines()[0].removeprefix("gitdir: "))
        hook_dir = git_dir / "hooks"

    hook_path = hook_dir / "pre-commit"

    # Check if hook already exists
    if hook_path.exists() and not args.force:
        existing = hook_path.read_text()
        if "PromptGuard pre-commit hook" not in existing:
            print(f"⚠   {hook_path} already exists and is not a PromptGuard hook.")
            print(f"    Use --force to overwrite, or remove it first.")
            sys.exit(1)
        # Replacing our own hook is fine even without --force

    hook_dir.mkdir(parents=True, exist_ok=True)
    hook_path.write_text(_PRECOMMIT_SCRIPT_TEMPLATE)
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"✅  PromptGuard pre-commit hook installed to: {hook_path}")
    print(f"    The hook will validate AI instruction files on every commit.")
    print(f"    Blocked files (BLOCK_SESSION / QUARANTINE) will prevent the commit.")
    print(f"    Normal commits (no instruction files staged) pass through.")


_PRECOMMIT_SCRIPT_TEMPLATE = r"""#!/bin/sh
# PromptGuard pre-commit hook
# Generated by `promptguard install-precommit`. Do not edit manually.
#
# Exit codes: 0 = allow commit, 1 = block (policy violation), 2 = config error

set -e

# Known AI provider instruction files (relative to repo root)
# Maps each staged file to its provider for validate-file

resolve_provider() {
    case "$1" in
        CLAUDE.md|.claude/CLAUDE.md)
            echo "claude_code" ;;
        .github/copilot-instructions.md|.copilot-instructions.md)
            echo "github_copilot" ;;
        .cursorrules|.cursor/rules|.cursor/rules.md)
            echo "cursor" ;;
        .continuerc.json|.continue/config.json|.continue/config.yaml)
            echo "continue_dev" ;;
        .codeium/instructions.md|.windsurf/rules.md)
            echo "codeium" ;;
        .promptguard.yaml)
            echo "generic" ;;
        *)
            echo "generic" ;;
    esac
}

# Get staged files
staged_files=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null)
if [ -z "$staged_files" ]; then
    exit 0
fi

blocked=0
config_error=0

# Use while-read to handle filenames with spaces correctly
echo "$staged_files" | while IFS= read -r file; do
    if [ -z "$file" ]; then
        continue
    fi

    # Check if this file is a known instruction file
    is_instruction=0
    case "$file" in
        CLAUDE.md|.claude/CLAUDE.md)
            is_instruction=1 ;;
        .github/copilot-instructions.md|.copilot-instructions.md)
            is_instruction=1 ;;
        .cursorrules|.cursor/rules|.cursor/rules.md)
            is_instruction=1 ;;
        .continuerc.json|.continue/config.json|.continue/config.yaml)
            is_instruction=1 ;;
        .codeium/instructions.md|.windsurf/rules.md)
            is_instruction=1 ;;
        .promptguard.yaml)
            is_instruction=1 ;;
    esac

    if [ "$is_instruction" = "1" ]; then
        provider=$(resolve_provider "$file")
        result=$(promptguard validate-file --file "$file" --provider "$provider" 2>&1) || {
            echo "PromptGuard pre-commit: config error for $file" >&2
            echo "$result" >&2
            config_error=1
            continue
        }
        # Check decision in output
        if echo "$result" | grep -qE "BLOCK_SESSION|QUARANTINE"; then
            echo "🔴  PromptGuard pre-commit: blocked commit" >&2
            echo "    File: $file" >&2
            echo "$result" | grep -E "BLOCK_SESSION|QUARANTINE|\[CRITICAL\]|\[HIGH\]" >&2
            blocked=1
        elif echo "$result" | grep -q "Decision: ALLOW_WITH_REDACTION"; then
            echo "🟡  PromptGuard: $file has redactions (allowed with changes)" >&2
        else
            echo "✅  PromptGuard: $file passed" >&2
        fi
    fi
done

if [ "$config_error" = "1" ]; then
    exit 2
fi
if [ "$blocked" = "1" ]; then
    exit 1
fi
exit 0
"""

_WRAPPER_SCRIPT_TEMPLATE = '''#!/bin/sh
# {{WRAPPER_NAME}} — PromptGuard-wrapped Claude Code
# Generated by PromptGuard. Do not edit manually.
# To change the wrapper name, edit .promptguard.yaml: wrapper.command_name

set -e

WRAPPER_NAME="{{WRAPPER_NAME}}"
PROMPTGUARD_CONFIG=".promptguard.yaml"

# Find nearest .promptguard.yaml (CWD → home)
find_config() {{
    dir="$(pwd)"
    while [ -n "$dir" ]; do
        if [ -f "$dir/$PROMPTGUARD_CONFIG" ]; then
            echo "$dir/$PROMPTGUARD_CONFIG"
            return 0
        fi
        if [ "$dir" = "$(getent passwd "$(whoami)" | cut -d: -f6)" ]; then
            break
        fi
        dir="$(dirname "$dir")"
    done
    # Fall back to default location
    echo "$HOME/.promptguard/config.yaml"
}}

CONFIG_PATH="$(find_config)"

# Find instruction file
find_instr_file() {{
    if [ -f "CLAUDE.md" ]; then
        echo "CLAUDE.md"
    elif [ -f ".claude/CLAUDE.md" ]; then
        echo ".claude/CLAUDE.md"
    elif [ -f ".github/copilot-instructions.md" ]; then
        echo ".github/copilot-instructions.md"
    elif [ -f ".cursorrules" ]; then
        echo ".cursorrules"
    elif [ -f ".continuerc.json" ]; then
        echo ".continuerc.json"
    else
        echo ""
    fi
}}

# Validate if config exists and instruction file found
if [ -f "$CONFIG_PATH" ] || [ -f "$HOME/.promptguard/config.yaml" ]; then
    INSTR_FILE="$(find_instr_file)"
    if [ -n "$INSTR_FILE" ] && [ -f "$INSTR_FILE" ]; then
        RESULT="$(promptguard validate-file --file "$INSTR_FILE" --provider claude_code 2>&1)"
        # Check decision in output
        if echo "$RESULT" | grep -q "BLOCK_SESSION|QUARANTINE"; then
            echo "$WRAPPER_NAME: Instruction file blocked by PromptGuard policy."
            echo "$RESULT"
            exit 1
        fi
    fi
fi

# All checks passed — invoke Claude Code
if command -v claude >/dev/null 2>&1; then
    exec claude "$@"
else
    echo "$WRAPPER_NAME: claude binary not found."
    echo "Install Claude Code or ensure it is on your PATH."
    exit 2
fi
'''

def cmd_install_hooks(args):
    """Write .claude/settings.json with PromptGuard PreToolUse hook."""
    import json
    root = Path(args.workspace or ".")
    claude_dir = root / ".claude"
    claude_dir.mkdir(exist_ok=True)
    settings_path = claude_dir / "settings.json"

    existing: dict = {}
    if settings_path.exists():
        try:
            existing = json.loads(settings_path.read_text())
        except json.JSONDecodeError:
            pass

    port = args.port or 7474
    hook_command = (
        f'curl -s -X POST http://127.0.0.1:{port}/hook/pre-tool '
        f'-H "Content-Type: application/json" '
        f'-d "{{\\"tool_name\\":\\"$CLAUDE_TOOL_NAME\\",\\"tool_input\\":$CLAUDE_TOOL_INPUT_JSON}}" '
        f'| python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d[\'allowed\'] else 1)"'
    )

    hooks = existing.get("hooks", {})
    pre = hooks.get("PreToolUse", [])
    pre.append({
        "matcher": "*",
        "hooks": [{"type": "command", "command": hook_command}],
    })
    hooks["PreToolUse"] = pre
    existing["hooks"] = hooks

    settings_path.write_text(json.dumps(existing, indent=2))
    print(f"✅  Claude Code hooks written to: {settings_path}")
    print(f"   PromptGuard PreToolUse hook active on port {port}")


def cmd_audit(args):
    from promptguard.config import load_config
    from promptguard.audit.logger import AuditLogger
    cfg = load_config()
    audit = AuditLogger(cfg.audit)
    if args.audit_cmd == "stats":
        print(json.dumps(audit.stats(), indent=2))
    elif args.audit_cmd == "prune":
        n = audit.prune()
        print(f"Pruned {n} records older than {cfg.audit.retention_days} days.")
    elif args.audit_cmd == "recent":
        events = audit.recent(20)
        print(json.dumps(events, indent=2))


def cmd_test_prompt(args):
    from promptguard.config import load_config
    from promptguard.models import ProxyRequest
    from promptguard.pipeline import build_context, run_pipeline

    cfg = load_config()
    req = ProxyRequest(
        prompt=args.prompt,
        language=args.language,
        provider=args.provider or "generic",
    )
    ctx = build_context(req)
    ctx = run_pipeline(ctx, cfg)

    icon = {"ALLOW": "✅", "ALLOW_WITH_REDACTION": "🟡", "QUARANTINE": "🟠", "BLOCK_SESSION": "🔴"}
    print(f"\n── PromptGuard Dry Run ─────────────────────────────────")
    print(f"Decision      : {icon.get(ctx.decision.value, '?')} {ctx.decision.value}")
    if ctx.block_reason:
        print(f"Block reason  : {ctx.block_reason}")
    print(f"Redactions    : {len(ctx.redactions)}")
    print(f"Findings      : {len(ctx.all_findings)}")
    for f in ctx.all_findings:
        print(f"  [{f.severity.value.upper():8}] {f.rule_id}: {f.message[:70]}")
    if ctx.envelope:
        print(f"Envelope hash : {ctx.envelope.envelope_hash}")
        print(f"\nRendered envelope (first 600 chars):")
        print(ctx.envelope.render()[:600])
    print("────────────────────────────────────────────────────────\n")


def main():
    p = argparse.ArgumentParser(prog="promptguard")
    sub = p.add_subparsers(dest="command")

    # generate-key
    pgk = sub.add_parser("generate-key", help="Generate a 256-bit HMAC signing key")
    pgk.add_argument("--key-path", default=None,
                     help="Where to write the key (default: ~/.promptguard/signing.key)")

    # sign-policy
    psp = sub.add_parser("sign-policy", help="Sign a .promptguard.yaml policy file")
    psp.add_argument("--config", required=True, help="Path to .promptguard.yaml")
    psp.add_argument("--key-path", default=None, help="Path to signing key (overrides default)")

    # verify-policy
    pvp = sub.add_parser("verify-policy", help="Verify a signed policy file")
    pvp.add_argument("--config", required=True)
    pvp.add_argument("--key-path", default=None)
    pvp.add_argument("--mode", choices=["strict", "warn", "off"], default="strict")

    # serve
    ps = sub.add_parser("serve")
    ps.add_argument("--host", default="127.0.0.1")
    ps.add_argument("--port", type=int, default=7474)
    ps.add_argument("--config")
    ps.add_argument("--reload", action="store_true")

    # validate config
    pv = sub.add_parser("validate")
    pv.add_argument("--config", required=True)

    # validate instruction file
    pvf = sub.add_parser("validate-file")
    pvf.add_argument("--file", required=True)
    pvf.add_argument("--provider", default="generic")
    pvf.add_argument("--output", default=None, help="Write sanitized output to file")

    # scan workspace
    psw = sub.add_parser("scan-workspace")
    psw.add_argument("--workspace", default=".")

    # install claude code hooks
    pih = sub.add_parser("install-hooks")
    pih.add_argument("--workspace", default=".")
    pih.add_argument("--port", type=int, default=7474)

    # install pre-commit hook
    ppk = sub.add_parser("install-precommit", help="Install a git pre-commit hook that validates AI instruction files")
    ppk.add_argument("--path", default=None, help="Target directory for the hook (default: .git/hooks)")
    ppk.add_argument("--force", action="store_true", help="Overwrite existing pre-commit hook")

    # install wrapper
    piw = sub.add_parser("install-wrapper")
    piw.add_argument("--name", default=None, help="Name of the wrapper binary (default: dmcslab-code, or wrapper.command_name from config)")
    piw.add_argument("--path", default="/usr/local/bin", help="Install path prefix (default: /usr/local/bin)")

    # audit
    pa = sub.add_parser("audit")
    pa.add_argument("audit_cmd", choices=["stats", "prune", "recent"])

    # test prompt
    pt = sub.add_parser("test-prompt")
    pt.add_argument("--prompt", required=True)
    pt.add_argument("--language")
    pt.add_argument("--provider", default="generic")

    args = p.parse_args()
    dispatch = {
        "generate-key":   cmd_generate_key,
        "sign-policy":    cmd_sign_policy,
        "verify-policy":  cmd_verify_policy,
        "serve":          cmd_serve,
        "validate":       cmd_validate,
        "validate-file":  cmd_validate_file,
        "scan-workspace": cmd_scan_workspace,
        "install-hooks":  cmd_install_hooks,
        "install-precommit": cmd_install_precommit,
        "install-wrapper": cmd_install_wrapper,
        "audit":          cmd_audit,
        "test-prompt":    cmd_test_prompt,
    }
    fn = dispatch.get(args.command)
    if fn:
        fn(args)
    else:
        p.print_help()


if __name__ == "__main__":
    main()