#!/bin/bash
# upgrade.sh — Pull latest PromptGuard and restart

set -e

echo "Upgrading PromptGuard..."
echo ""

# Check for sourced config (do not overwrite user's config)
if [ -f "$HOME/.promptguard/config.yaml" ]; then
  echo "[OK] Existing config found at ~/.promptguard/config.yaml"
  echo "     Your configuration will be preserved."
elif [ -f ".promptguard.yaml" ]; then
  echo "[OK] Workspace config found at .promptguard.yaml"
else
  echo "[WARN] No config file found. Copy .promptguard.yaml from the repo after upgrade."
fi

# Pull latest if this is a git repo
if [ -d ".git" ]; then
  echo ""
  echo "Pulling latest from git..."
  git pull origin main || git pull origin master || echo "[SKIP] Not a git clone or no remote"
else
  echo ""
  echo "[INFO] Not a git repo — install latest with:"
  echo "       pip install --upgrade promptguard"
fi

echo ""
echo "Reinstalling..."
pip install -e . --quiet

echo ""
echo "Upgrade complete."
echo ""
echo "Data preservation:"
echo "  ~/.promptguard/config.yaml  — preserved (upgrade does not modify it)"
echo "  ~/.promptguard/audit.db     — preserved"
echo "  ~/.promptguard/audit.jsonl  — preserved"
echo "  Session keys in memory      — cleared (restart required)"
echo ""
echo "To restart: ./start.sh  or  promptguard serve"