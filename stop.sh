#!/bin/bash
# stop.sh — Stop the PromptGuard service

set -e

echo "Stopping PromptGuard service..."

# Find and kill the running server process
if command -v lsof >/dev/null 2>&1; then
  PID=$(lsof -ti:7474 2>/dev/null || true)
  if [ -n "$PID" ]; then
    echo "Killing process on port 7474 (PID: $PID)..."
    kill "$PID" 2>/dev/null || true
    sleep 1
    # Force-kill if still alive
    if lsof -ti:7474 >/dev/null 2>&1; then
      kill -9 "$PID" 2>/dev/null || true
    fi
  fi
elif command -v fuser >/dev/null 2>&1; then
  fuser -k 7474/tcp 2>/dev/null || true
else
  # Fallback: kill by process name
  pkill -f "promptguard serve" 2>/dev/null || true
  pkill -f "python.*promptguard" 2>/dev/null || true
fi

# Also kill any leftover session key processes
pkill -f "promptguard-session" 2>/dev/null || true

echo "PromptGuard service stopped."
echo "To restart: promptguard serve"