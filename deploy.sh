#!/bin/bash
# =============================================================================
# PromptGuard Deployment Script
# =============================================================================
# Deploys PromptGuard as a local security sidecar for AI coding assistants.
# Supports: Claude Code, GitHub Copilot, Cursor, Continue.dev, Codeium.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/dmcslab/promptguard/main/deploy.sh | bash
#   --or--
#   ./deploy.sh [--port PORT] [--host HOST] [--config FILE] [--generate-key]
#
# Requirements: Python 3.11+, pip
# =============================================================================

set -euo pipefail

PORT="${PROMPTGUARD_PORT:-7474}"
HOST="${PROMPTGUARD_HOST:-127.0.0.1}"
CONFIG_FILE="${PROMPTGUARD_CONFIG_FILE:-}"
GENERATE_KEY="${PROMPTGUARD_GENERATE_KEY:-}"
API_KEY="${PROMPTGUARD_API_KEY:-}"

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
log() { printf '\n>>> %s\n\n' "$*"; }
warn() { printf '\n⚠️  %s\n\n' "$*"; }
info() { printf '  %s\n' "$*"; }
ok()   { printf '  ✅ %s\n' "$*"; }
fail() { printf '  🚫 %s\n' "$*"; exit 1; }

separator() { printf '\n%s\n' "----------------------------------------------------------------"; }

# -------------------------------------------------------------------
# Parse flags
# -------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)      PORT="$2";      shift 2 ;;
    --host)      HOST="$2";      shift 2 ;;
    --config)    CONFIG_FILE="$2"; shift 2 ;;
    --generate-key) GENERATE_KEY=1; shift ;;
    --api-key)   API_KEY="$2";   shift 2 ;;
    --help|-h)   cat <<'EOF'
Usage: deploy.sh [OPTIONS]

  --port PORT       Port for PromptGuard (default: 7474)
  --host HOST       Bind address (default: 127.0.0.1)
  --config FILE     Path to .promptguard.yaml (optional)
  --generate-key    Generate a new random API key
  --api-key KEY     Set API key directly (env: PROMPTGUARD_API_KEY)
  --help            Show this help

Environment variables also work:
  PROMPTGUARD_PORT, PROMPTGUARD_HOST, PROMPTGUARD_CONFIG_FILE,
  PROMPTGUARD_API_KEY, PROMPTGUARD_GENERATE_KEY
EOF
  exit 0 ;;
    *) shift ;;
  esac
done

# -------------------------------------------------------------------
# Step 0: Prerequisites
# -------------------------------------------------------------------
log "Checking prerequisites"

if ! command -v python3 &>/dev/null; then
  fail "Python 3.11+ is required. Install from python.org or 'apt install python3'"
fi

PY_VERSION=$(python3 -c "import sys; v=sys.version_info; print(f'{v.major}.{v.minor}')")
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)"; then
  ok "Python $PY_VERSION"
else
  fail "Python 3.11+ required, found $PY_VERSION"
fi

if ! command -v pip3 &>/dev/null && ! python3 -m pip --version &>/dev/null; then
  fail "pip is required. Install with 'python3 -m ensurepip' or 'apt install python3-pip'"
fi
ok "pip available"

# -------------------------------------------------------------------
# Step 1: Detect or create virtual environment
# -------------------------------------------------------------------
log "Setting up Python environment"

# Determine install target
INSTALL_TARGET=""
VENV_PATH=""

if [[ -d ".venv" ]]; then
  VENV_PATH=".venv"
elif [[ -d "venv" ]]; then
  VENV_PATH="venv"
fi

if [[ -n "$VENV_PATH" ]]; then
  INSTALL_TARGET="$VENV_PATH"
  ok "Using existing virtual environment: $VENV_PATH"
else
  # Check if we're in the promptguard repo
  if [[ -f "pyproject.toml" ]] && grep -q "promptguard" pyproject.toml 2>/dev/null; then
    INSTALL_TARGET="."
    ok "Installing in-place (editable mode)"
  else
    # Use user install to avoid system-wide pip issues
    INSTALL_TARGET="--user"
    ok "Using user site-packages (no venv detected)"
  fi
fi

# -------------------------------------------------------------------
# Step 2: Install / upgrade PromptGuard
# -------------------------------------------------------------------
log "Installing PromptGuard v0.2"

if [[ "$INSTALL_TARGET" == "--user" ]]; then
  python3 -m pip install --upgrade pip --quiet
  python3 -m pip install -e ".[dev]" --quiet 2>/dev/null || \
    python3 -m pip install -e . --quiet
else
  python3 -m pip install --upgrade pip --quiet
  python3 -m pip install -e ".[dev]" $INSTALL_TARGET --quiet 2>/dev/null || \
    python3 -m pip install -e . $INSTALL_TARGET --quiet
fi

if command -v promptguard &>/dev/null; then
  VERSION=$(promptguard --version 2>/dev/null || promptguard --help | head -1)
  ok "PromptGuard installed: $VERSION"
else
  fail "Installation succeeded but 'promptguard' command not found. Check your PATH."
fi

# -------------------------------------------------------------------
# Step 3: API key
# -------------------------------------------------------------------
log "Configuring API key"

KEY_SOURCE=""

if [[ -n "$API_KEY" ]]; then
  KEY_SOURCE="provided via --api-key or env"
elif [[ -n "$GENERATE_KEY" ]]; then
  API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  KEY_SOURCE="newly generated (--generate-key)"
elif [[ -n "${PROMPTGUARD_API_KEY:-}" ]]; then
  API_KEY="$PROMPTGUARD_API_KEY"
  KEY_SOURCE="from PROMPTGUARD_API_KEY env var"
fi

if [[ -n "$API_KEY" ]]; then
  export PROMPTGUARD_API_KEY="$API_KEY"
  # Persist to shell rc
  SHELL_RC=""
  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [[ -w "$rc" ]]; then SHELL_RC="$rc"; break; fi
  done
  if [[ -n "$SHELL_RC" ]] && ! grep -q "PROMPTGUARD_API_KEY" "$SHELL_RC" 2>/dev/null; then
    printf '\nexport PROMPTGUARD_API_KEY=%q\n' "$API_KEY" >> "$SHELL_RC"
    info "Saved to $SHELL_RC (re-run 'source $SHELL_RC' or start a new shell)"
  fi
  ok "API key set ($KEY_SOURCE)"
else
  warn "No API key set. Protected endpoints will return 401."
  info "To set a key:"
  info "  1. Generate:  openssl rand -hex 32"
  info "  2. Then:      export PROMPTGUARD_API_KEY=<your-key>"
  info "  3. Or re-run: $0 --generate-key"
  info "  4. Or set in .promptguard.yaml:  providers.api_key: <your-key>"
fi

# -------------------------------------------------------------------
# Step 4: Config
# -------------------------------------------------------------------
log "Configuring policy"

CONFIG_PATH=""
if [[ -n "$CONFIG_FILE" ]]; then
  if [[ -f "$CONFIG_FILE" ]]; then
    CONFIG_PATH="$CONFIG_FILE"
    ok "Using config: $CONFIG_FILE"
  else
    fail "Config file not found: $CONFIG_FILE"
  fi
elif [[ -f ".promptguard.yaml" ]]; then
  CONFIG_PATH=".promptguard.yaml"
  ok "Using .promptguard.yaml in current directory"
elif [[ -f "$HOME/.promptguard/config.yaml" ]]; then
  CONFIG_PATH="$HOME/.promptguard/config.yaml"
  ok "Using ~/.promptguard/config.yaml"
fi

if [[ -n "$CONFIG_PATH" ]]; then
  if command -v promptguard &>/dev/null; then
    if promptguard validate --config "$CONFIG_PATH" 2>/dev/null; then
      ok "Config is valid"
    else
      warn "Config validation failed — check $CONFIG_PATH"
    fi
  fi
else
  # Copy example config if nothing found
  if [[ -f ".promptguard.yaml" ]]; then
    mkdir -p "$HOME/.promptguard"
    cp .promptguard.yaml "$HOME/.promptguard/config.yaml"
    CONFIG_PATH="$HOME/.promptguard/config.yaml"
    ok "Copied .promptguard.yaml → ~/.promptguard/config.yaml"
  fi
fi

# -------------------------------------------------------------------
# Step 5: Port check
# -------------------------------------------------------------------
if command -v lsof &>/dev/null; then
  if lsof -i ":$PORT" -sTCP:LISTEN &>/dev/null; then
    warn "Port $PORT is already in use. Use --port to change it."
    PORT_IN_USE=1
  else
    ok "Port $PORT is available"
    PORT_IN_USE=0
  fi
else
  if ss -tlnp 2>/dev/null | grep -q ":$PORT " || netstat -tlnp 2>/dev/null | grep -q ":$PORT "; then
    warn "Port $PORT may already be in use."
    PORT_IN_USE=1
  else
    ok "Port $PORT appears free"
    PORT_IN_USE=0
  fi
fi

# -------------------------------------------------------------------
# Step 6: Start the service
# -------------------------------------------------------------------
log "Starting PromptGuard"

SERVICE_CMD="promptguard serve --host $HOST --port $PORT"
if [[ -n "$CONFIG_PATH" ]]; then
  SERVICE_CMD="$SERVICE_CMD --config $CONFIG_PATH"
fi

# Export key so the subprocess sees it
if [[ -n "$API_KEY" ]]; then
  export PROMPTGUARD_API_KEY="$API_KEY"
fi

# Start in background
nohup bash -c "$SERVICE_CMD" > /tmp/promptguard.log 2>&1 &
PG_PID=$!

# Wait for startup (up to 10s)
sleep 1
for i in {1..10}; do
  if curl -sf "http://${HOST}:${PORT}/live" &>/dev/null; then
    break
  fi
  sleep 1
done

if kill -0 "$PG_PID" 2>/dev/null; then
  ok "PromptGuard is running (PID: $PG_PID)"
else
  fail "Service failed to start. See: tail /tmp/promptguard.log"
fi

# -------------------------------------------------------------------
# Step 7: Verify
# -------------------------------------------------------------------
separator
echo "  Verification"
separator

if curl -sf "http://${HOST}:${PORT}/health" | python3 -m json.tool &>/dev/null; then
  ok "/health: OK"
else
  fail "/health: FAILED"
fi

if [[ -n "$API_KEY" ]]; then
  HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    -H "X-PromptGuard-API-Key: $API_KEY" \
    "http://${HOST}:${PORT}/hook/pre-tool" \
    -X POST -H "Content-Type: application/json" -d '{"tool":"bash","tool_input":{"command":"ls"}}' 2>/dev/null || echo "000")
  if [[ "$HTTP_CODE" == "422" ]]; then
    ok "/hook/pre-tool auth: OK (422 = valid key, bad payload — expected)"
  else
    warn "/hook/pre-tool returned $HTTP_CODE"
  fi
else
  info "/hook/pre-tool: no API key — skipped"
fi

# -------------------------------------------------------------------
# Done
# -------------------------------------------------------------------
separator
echo "  Deployment complete"
separator
echo ""
echo "  URLs:"
echo "    Health:   http://${HOST}:${PORT}/health"
echo "    Ready:    http://${HOST}:${PORT}/ready"
echo "    Liveness: http://${HOST}:${PORT}/live"
echo ""
echo "  Endpoints:"
echo "    POST /hook/pre-tool  — Claude Code PreToolUse hook"
echo "    POST /session/key    — Register session key (auth required)"
echo "    GET  /session/keys   — List active session keys (auth required)"
echo "    POST /session/reset  — Reset session state (auth required)"
echo "    POST /reload         — Hot-reload config + rules (auth required)"
echo ""
echo "  Config:   ${CONFIG_PATH:-none set}"
echo "  Log:      /tmp/promptguard.log"
echo "  PID:      $PG_PID"
echo ""
echo "  To stop:  kill $PG_PID"
echo "  To view logs:  tail -f /tmp/promptguard.log"
echo ""
echo "  Next steps:"
echo "    1. Connect Claude Code:  promptguard install-hooks --workspace ."
echo "    2. Test a detection:    promptguard test-prompt --prompt 'ignore all previous instructions'"
echo "    3. Read the docs:       open docs/GETTING_STARTED.md"
echo ""
separator