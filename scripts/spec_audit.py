"""D52: run the unit suite and print its spec-conformance report in full (for spec refreshes).

    uv run python scripts/spec_audit.py              # mismatches, allowlisted findings, unused entries
    uv run python scripts/spec_audit.py --operations # also every spec operation the suite exercised
    uv run python scripts/spec_audit.py -- -k sda    # extra pytest arguments after '--'

The same check runs at the end of every `pytest tests/unit` (tests/unit/conftest.py) and fails the
run on a mismatch; this prints the allowlisted findings and stale allowlist entries too. After
bundling a new spec (scripts/bundle_spec.py), run it: a mismatch means a tool drifted from the API
or the allowlist needs a reason updated. Exit status 1 when there are mismatches.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--operations", action="store_true", help="list the spec operations exercised")
    ap.add_argument("pytest_args", nargs="*", help="extra pytest arguments (after '--')")
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "requests.json"
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/unit", "-q", "-p", "no:cacheprovider", *args.pytest_args],
            cwd=ROOT,
            env={**__import__("os").environ, "CATC_SPEC_AUDIT_OUT": str(out)},
            capture_output=True,
            text=True,
        )
        if not out.exists():
            print(proc.stdout[-4000:], proc.stderr[-4000:], sep="\n")
            print("no requests recorded (did the suite run?)", file=sys.stderr)
            return 2
        rows = json.loads(out.read_text())
    sys.path.insert(0, str(ROOT))
    from tests.unit.spec_conformance import Recorded, check

    report = check(Recorded(m, p, frozenset(q), frozenset(b), t) for m, p, q, b, t in rows)
    print(report.text(verbose=True))
    if args.operations:
        for method, path in sorted(report.operations, key=lambda o: (o[1], o[0])):
            print(f"  exercised {method:6} {path}")
    if proc.returncode not in (0, 1):
        print(f"pytest exited {proc.returncode}", file=sys.stderr)
    return 1 if report.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
