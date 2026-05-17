#!/bin/bash
# uninstall.sh — Remove PromptGuard completely

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROMPTGUARD_HOME="$HOME/.promptguard"

echo "Uninstalling PromptGuard..."
echo ""

# Stop the service first
echo "Stopping PromptGuard service..."
if command -v lsof >/dev/null 2>&1; then
  PID=$(lsof -ti:7474 2>/dev/null || true)
  [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
elif command -v fuser >/dev/null 2>&1; then
  fuser -k 7474/tcp 2>/dev/null || true
else
  pkill -f "promptguard serve" 2>/dev/null || true
fi

# Remove CLI wrapper
echo "Removing CLI wrapper (dmcslab-code)..."
rm -f "$HOME/.local/bin/dmcslab-code" 2>/dev/null || true
rm -f "$HOME/bin/dmcslab-code" 2>/dev/null || true

# Remove VS Code extension hooks
echo "Removing Claude Code hooks..."
rm -f "$SCRIPT_DIR/.claude/settings.json" 2>/dev/null || true

# Uninstall Python package
echo "Uninstalling Python package..."
pip uninstall promptguard -y 2>/dev/null || pip uninstall promptguard -y 2>/dev/null

# Ask about data directory
if [ -d "$PROMPTGUARD_HOME" ]; then
  echo ""
  echo "PromptGuard data directory: $PROMPTGUARD_HOME"
  read -p "Delete all data (config, audit logs, session keys)? [y/N] " -n 1 -r
  echo ""
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$PROMPTGUARD_HOME"
    echo "Data directory removed."
  else
    echo "Data directory preserved at: $PROMPTGUARD_HOME"
  fi
fi

echo ""
echo "Uninstall complete."
echo "If you used the VS Code extension, manually disable it in VS Code (Extensions panel)."