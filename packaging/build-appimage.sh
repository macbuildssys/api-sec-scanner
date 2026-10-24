#!/usr/bin/env bash
# Builds a single-file AppImage with its own Python, so nothing needs to be installed.
# Needs internet access to download python-build-standalone and appimagetool (x86_64).
# Usage: packaging/build-appimage.sh [output folder]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$HERE/dist}"
CACHE="${CACHE:-$HERE/.cache/packaging}"
PBS_URL="${PBS_URL:-}"
TOOL_URL="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
VERSION="$(python3 -c "import re,sys;print(re.search(r'__version__ = \"(.+?)\"', open(sys.argv[1]).read()).group(1))" "$HERE/api_scanner/__init__.py")"
mkdir -p "$CACHE" "$OUT"

if [ ! -f "$CACHE/python.tar.gz" ]; then
  if [ -z "$PBS_URL" ]; then
    PBS_URL="$(python3 - <<'PY'
import json, urllib.request
req = urllib.request.Request("https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest", headers={"User-Agent": "api-sec-scanner-build"})
assets = json.load(urllib.request.urlopen(req))["assets"]
for a in assets:
    n = a["name"]
    if n.startswith("cpython-3.12.") and n.endswith("x86_64-unknown-linux-gnu-install_only.tar.gz"):
        print(a["browser_download_url"]); break
PY
)"
  fi
  curl -fsSL "$PBS_URL" -o "$CACHE/python.tar.gz"
fi
[ -x "$CACHE/appimagetool" ] || { curl -fsSL "$TOOL_URL" -o "$CACHE/appimagetool"; chmod +x "$CACHE/appimagetool"; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
APPDIR="$WORK/api-sec-scanner.AppDir"
mkdir -p "$APPDIR/usr"
tar -xzf "$CACHE/python.tar.gz" -C "$APPDIR/usr"          # creates usr/python
PYBIN="$APPDIR/usr/python/bin/python3"
"$PYBIN" -m pip install --quiet --no-warn-script-location --no-compile "$HERE"

# Make the bundle smaller: no pip, tests, headers or tkinter.
SITE="$("$PYBIN" -c 'import sysconfig;print(sysconfig.get_paths()["purelib"])')"
LIBDIR="$(dirname "$SITE")"
rm -rf "$SITE"/pip* "$SITE"/setuptools* "$SITE"/wheel* "$SITE"/_distutils_hack "$SITE"/pkg_resources
rm -rf "$APPDIR/usr/python/include" "$APPDIR/usr/python/share" "$LIBDIR"/test "$LIBDIR"/idlelib "$LIBDIR"/tkinter "$LIBDIR"/turtledemo \
       "$LIBDIR"/lib2to3 "$LIBDIR"/ensurepip "$LIBDIR"/config-3*
find "$APPDIR/usr/python/bin" -type f ! -name 'python3*' -delete 2>/dev/null || true
find "$APPDIR" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$APPDIR/usr/python/lib" -name 'libtcl*' -o -name 'libtk*' | xargs -r rm -rf
"$PYBIN" -m compileall -q "$SITE/api_scanner" >/dev/null 2>&1 || true

cat > "$APPDIR/AppRun" <<'APPRUN'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
export PYTHONHOME="$HERE/usr/python"
export PYTHONNOUSERSITE=1
export PYTHONDONTWRITEBYTECODE=1
exec "$HERE/usr/python/bin/python3" -m api_scanner "$@"
APPRUN
chmod 755 "$APPDIR/AppRun"
cat > "$APPDIR/api-sec-scanner.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=api-sec-scanner
Comment=Detect vulnerabilities in REST APIs and websites
Exec=api-sec-scanner
Icon=api-sec-scanner
Categories=Development;Security;
Terminal=true
DESKTOP
cp "$HERE/packaging/api-sec-scanner.svg" "$APPDIR/api-sec-scanner.svg"
cp "$HERE/LICENSE" "$APPDIR/LICENSE"

OUTFILE="$OUT/api-sec-scanner-v${VERSION}-x86_64.AppImage"
ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$CACHE/appimagetool" --no-appstream "$APPDIR" "$OUTFILE" >/dev/null
chmod +x "$OUTFILE"
echo "Built $OUTFILE"
