"""Starts a deliberately vulnerable (or hardened) demo API on your own machine.

Usage:
    python tools/demo_server.py vulnerable 8099      a leaky API (prints two user tokens)
    python tools/demo_server.py hardened 8098       the same API with the holes fixed
    python tools/demo_server.py site 8097           a leaky website
    python tools/demo_server.py hardened-site 8096  the same website with the holes fixed

It listens on 127.0.0.1 only, so nobody else on the network can reach it.
"""
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aiohttp import web  # noqa: E402

from tests.apps import issue_token, make_app  # noqa: E402
from tests.site import make_site  # noqa: E402

mode = sys.argv[1] if len(sys.argv) > 1 else "vulnerable"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8099
if mode in ("site", "hardened-site"):
    print(f"Demo website ({'leaky' if mode == 'site' else 'hardened'}) on http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop.")
    web.run_app(make_site(mode == "site"), host="127.0.0.1", port=port, access_log=None, print=None)
    sys.exit(0)
vulnerable = mode.startswith("vuln")
print(f"Demo API ({'vulnerable' if vulnerable else 'hardened'}) on http://127.0.0.1:{port}")
print(f"Spec:    http://127.0.0.1:{port}/openapi.json")
print(f"Token A: {issue_token('alice', vulnerable)}")
print(f"Token B: {issue_token('bob', vulnerable)}")
print("Press Ctrl+C to stop.")
web.run_app(make_app(vulnerable), host="127.0.0.1", port=port, access_log=None, print=None)
