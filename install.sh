#!/usr/bin/env bash
# Sets up the private environment and adds the command "api-sec-scanner"
# to ~/.local/bin so it works from any folder and any shell, no activation needed.
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$HERE/scanner.sh"
"$HERE/scanner.sh" --version >/dev/null
"$HERE/.venv/bin/python" -m pip install --quiet --force-reinstall --no-deps "$HERE"
"$HERE/.venv/bin/api-sec-scanner" --version
mkdir -p "$HOME/.local/bin"
ln -sf "$HERE/scanner.sh" "$HOME/.local/bin/api-sec-scanner"
ln -sf "$HERE/scanner.sh" "$HOME/.local/bin/scan"
echo
echo "Installed. Open a NEW terminal and run: api-sec-scanner   (or: scan)"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) echo "Note: add ~/.local/bin to your PATH. In fish: fish_add_path ~/.local/bin";; esac
