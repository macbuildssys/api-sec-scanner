#!/usr/bin/env bash
# Builds a .deb that needs no pip and no virtual environment.
# The scanner and its libraries are bundled as plain Python files, so the package works with the
# system python3 (3.10 or newer) on any CPU. Usage: packaging/build-deb.sh [output folder]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$HERE/dist}"
PY="${PYTHON:-python3}"
VERSION="$("$PY" -c "import re,sys;print(re.search(r'__version__ = \"(.+?)\"', open(sys.argv[1]).read()).group(1))" "$HERE/api_scanner/__init__.py")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/api-sec-scanner_${VERSION}_all"
LIB="$ROOT/usr/lib/api-sec-scanner"
mkdir -p "$LIB" "$ROOT/DEBIAN" "$ROOT/usr/bin" "$ROOT/usr/share/doc/api-sec-scanner" "$OUT"

# Libraries for Python 3.10 and newer. The compiled parts are left out on purpose: every one of
# these libraries has a pure Python fallback, which keeps the package independent of the CPU and Python version.
"$PY" -m pip install --quiet --no-compile --target "$LIB" --no-deps "$HERE"
"$PY" -m pip download --quiet --dest "$WORK/wheels" --only-binary=:all: --python-version 3.10 --platform manylinux2014_x86_64 --platform any \
  "aiohttp>=3.9" "click>=8.1" "cvss>=3.4" "pyyaml>=6.0" "rich>=13.0" "typing_extensions>=4.1" "async-timeout>=4.0,<6"
for wheel in "$WORK"/wheels/*.whl; do "$PY" -m zipfile -e "$wheel" "$LIB"; done
find "$LIB" \( -name '*.so' -o -name '*.so.*' -o -name '*.pyd' -o -name '*.c' -o -name '*.pyx' -o -name '*.pxd' -o -name '*.h' \) -delete
find "$LIB" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$LIB" -name '*.dist-info' -type d -prune -exec rm -rf {} +
rm -rf "$LIB/bin" "$LIB"/tests

cat > "$ROOT/usr/bin/api-sec-scanner" <<'LAUNCHER'
#!/bin/sh
# Runs the scanner with the system Python and the libraries bundled in /usr/lib/api-sec-scanner.
PYTHONPATH=/usr/lib/api-sec-scanner${PYTHONPATH:+:$PYTHONPATH}
AIOHTTP_NO_EXTENSIONS=1 MULTIDICT_NO_EXTENSIONS=1 YARL_NO_EXTENSIONS=1 FROZENLIST_NO_EXTENSIONS=1 PROPCACHE_NO_EXTENSIONS=1
export PYTHONPATH AIOHTTP_NO_EXTENSIONS MULTIDICT_NO_EXTENSIONS YARL_NO_EXTENSIONS FROZENLIST_NO_EXTENSIONS PROPCACHE_NO_EXTENSIONS
exec python3 -m api_scanner "$@"
LAUNCHER
chmod 755 "$ROOT/usr/bin/api-sec-scanner"
ln -s api-sec-scanner "$ROOT/usr/bin/scan"

cp "$HERE/LICENSE" "$ROOT/usr/share/doc/api-sec-scanner/copyright"
SIZE="$(du -sk "$ROOT/usr" | cut -f1)"
cat > "$ROOT/DEBIAN/control" <<CONTROL
Package: api-sec-scanner
Version: $VERSION
Section: utils
Priority: optional
Architecture: all
Depends: python3 (>= 3.10)
Recommends: chromium | chromium-browser | google-chrome-stable
Installed-Size: $SIZE
Maintainer: macbuildssys <noreply@users.noreply.github.com>
Homepage: https://github.com/macbuildssys/api-sec-scanner
Description: Security scanner for REST APIs and websites
 Detects vulnerabilities in REST APIs and websites. Scores each weakness with CVSS and maps it to the
 OWASP API Security Top 10, the OWASP Top 10, CWE and MITRE ATT&CK. Run it as api-sec-scanner or scan.
 The optional --browser mode crawls sites built with JavaScript and needs Chrome, Chromium or Edge.
CONTROL
cat > "$ROOT/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if [ "$1" = configure ] && command -v python3 >/dev/null 2>&1; then
  python3 -m compileall -q /usr/lib/api-sec-scanner >/dev/null 2>&1 || true
fi
exit 0
POSTINST
cat > "$ROOT/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
find /usr/lib/api-sec-scanner -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
exit 0
PRERM
chmod 755 "$ROOT/DEBIAN/postinst" "$ROOT/DEBIAN/prerm"
find "$ROOT" -type d -exec chmod 755 {} +
find "$LIB" -type f -exec chmod 644 {} +

dpkg-deb --root-owner-group --build "$ROOT" "$OUT/api-sec-scanner-v${VERSION}.deb" >/dev/null
echo "Built $OUT/api-sec-scanner-v${VERSION}.deb"
