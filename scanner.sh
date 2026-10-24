#!/usr/bin/env bash
# Launcher: runs the scanner in its own private virtual environment.
# On first run it creates .venv next to this file and installs the scanner.
# It never depends on which venv (if any) your shell has active.
set -e
SELF="$(readlink -f "${BASH_SOURCE[0]}")"
HOME_DIR="$(dirname "$SELF")"
VENV="$HOME_DIR/.venv"
if [ ! -x "$VENV/bin/api-sec-scanner" ]; then
  echo "First run: setting up a private environment in $VENV ..." >&2
  if ! python3 -m venv "$VENV" 2>/dev/null; then
    rm -rf "$VENV"
    echo "python3-venv is missing. Run: sudo apt install python3-venv python3-pip" >&2
    exit 1
  fi
  "$VENV/bin/python" -m pip install --quiet --upgrade pip
  "$VENV/bin/python" -m pip install --quiet "$HOME_DIR"
  echo "Setup finished." >&2
fi
exec "$VENV/bin/api-sec-scanner" "$@"
