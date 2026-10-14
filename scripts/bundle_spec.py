"""Bundle a Catalyst Center OpenAPI document as package data.

    uv run python scripts/bundle_spec.py path/to/swagger.json 3.2.2-75131

Strips `example`/`examples` (about 40% of the size, not used by the spec index), stamps
info.version/title, and writes src/catc_mcp/specs/catc-<version>.json.gz deterministically
(gzip mtime 0) so re-running it on the same input produces an identical file.
"""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path
from typing import Any

OUT_DIR = Path(__file__).resolve().parent.parent / "src" / "catc_mcp" / "specs"
DROP = {"example", "examples"}


def strip(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: strip(v) for k, v in node.items() if k not in DROP}
    if isinstance(node, list):
        return [strip(v) for v in node]
    return node


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, version = Path(sys.argv[1]), sys.argv[2]
    doc = strip(json.loads(src.read_text()))
    if isinstance(doc.get("components"), dict):
        doc["components"].pop("examples", None)
    doc.setdefault("info", {})
    doc["info"]["title"] = "Cisco Catalyst Center Intent API"
    doc["info"]["version"] = version
    raw = json.dumps(doc, separators=(",", ":"), sort_keys=True).encode()
    out = OUT_DIR / f"catc-{version.split('-')[0]}.json.gz"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    print(f"{out}: {len(doc.get('paths', {}))} paths, {out.stat().st_size / 1e6:.2f} MB")


if __name__ == "__main__":
    main()
