"""Regenerate api_scanner/data/attack_subset.json from the official ATT&CK STIX bundle.

Usage:
    python tools/refresh_attack.py path/to/enterprise-attack.json

The bundle is published at
https://github.com/mitre-attack/attack-stix-data (enterprise-attack/enterprise-attack.json).
Only the techniques the scanner maps findings to are kept, so the data file stays tiny.
Run this whenever MITRE ships a new ATT&CK release, then run the test suite: it fails
if a mapped technique was renamed, revoked or deprecated.
"""

import json
import sys
from pathlib import Path

# Make the package importable when the script is run from a source checkout.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api_scanner.knowledge import used_attack_ids  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "api_scanner" / "data" / "attack_subset.json"

def main(bundle_path: str) -> None:
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    objects = bundle["objects"]
    collection = next(o for o in objects if o["type"] == "x-mitre-collection")
    wanted = set(used_attack_ids())
    techniques = {}
    for obj in objects:
        if obj["type"] != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref["external_id"] in wanted:
                techniques[ref["external_id"]] = {
                    "name": obj["name"],
                    "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
                }
    missing = sorted(wanted - set(techniques))
    if missing:
        raise SystemExit(f"Techniques missing, revoked or deprecated in this release: {missing}")
    data = {
        "attack_version": collection.get("x_mitre_version"),
        "released": collection.get("modified", "")[:10],
        "techniques": dict(sorted(techniques.items())),
    }
    OUT.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(techniques)} techniques for ATT&CK v{data['attack_version']} to {OUT}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(sys.argv[1])
