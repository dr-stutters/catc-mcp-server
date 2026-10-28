"""D52: check the requests the unit suite makes against the bundled Catalyst Center spec.

The recorder (tests/unit/conftest.py) logs every request a test sends to the fake appliance: method,
path, query keys and top-level JSON body keys. At session end `check()` matches each one to an
operation of the bundled catc-3.2.2 spec (through the core spec loader) and reports:

- path:   no operation at that path (any method)
- method: the path exists, but not with this method
- query:  a query key the operation doesn't declare
- body:   a top-level body key the operation's request schema doesn't declare

Known exceptions live in tests/unit/spec_allowlist.py, each with a reason. `scripts/spec_audit.py`
prints the same report standalone (after a spec refresh).
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cache
from urllib.parse import parse_qsl

import httpx

from catc_mcp._core.spec import bundled
from catc_mcp._core.spec.index import Operation, SpecIndex, build_index
from catc_mcp.server import SPEC_RESOURCE

from .spec_allowlist import ALLOWLIST, Allowed

# Only requests to the API surfaces are checked (test-only URLs elsewhere are not the product's).
CHECKED_PREFIXES = ("/dna/", "/api/")


@dataclass(frozen=True)
class Recorded:
    method: str
    path: str
    query: frozenset[str] = frozenset()
    body: frozenset[str] = frozenset()
    test: str = ""


@dataclass(frozen=True)
class Finding:
    kind: str  # path | method | query | body
    method: str
    path: str  # the request path (template when matched)
    key: str = ""
    tests: tuple[str, ...] = ()

    def line(self) -> str:
        what = {
            "path": "no operation at this path",
            "method": "the path has no operation for this method",
            "query": f"query key {self.key!r} not in the spec",
            "body": f"body key {self.key!r} not in the request schema",
        }[self.kind]
        first = f" (e.g. {self.tests[0]})" if self.tests else ""
        return f"{self.method} {self.path}: {what}{first}"


@dataclass
class Report:
    requests: int = 0
    operations: set[tuple[str, str]] = field(default_factory=set)
    findings: list[Finding] = field(default_factory=list)
    allowed: list[tuple[Finding, Allowed]] = field(default_factory=list)
    unused_allowlist: list[Allowed] = field(default_factory=list)

    def text(self, *, verbose: bool = False) -> str:
        out = [
            f"spec conformance: {self.requests} requests, {len(self.operations)} spec operations, "
            f"{len(self.findings)} mismatches, {len(self.allowed)} allowlisted"
        ]
        out += ["  MISMATCH " + f.line() for f in self.findings]
        if verbose:
            out += [f"  allowed  {f.line()}  -- {a.reason}" for f, a in self.allowed]
            out += [
                f"  unused allowlist entry: {a.method} {a.path} {a.kind} {a.key}"
                for a in self.unused_allowlist
            ]
        return "\n".join(out)


# --- recording ------------------------------------------------------------------------------


def body_keys(content: bytes, content_type: str) -> frozenset[str]:
    """Top-level keys of a JSON body; for a list of objects, the union of the items' keys."""
    if not content or "json" not in content_type:
        return frozenset()
    try:
        data = json.loads(content)
    except ValueError:
        return frozenset()
    items = data if isinstance(data, list) else [data]
    return frozenset(k for it in items if isinstance(it, dict) for k in it)


def record(request: httpx.Request, test: str = "") -> Recorded | None:
    """The parts of a request the check needs, or None for a request outside the API surfaces."""
    path = request.url.raw_path.decode().split("?", 1)[0]
    if not path.startswith(CHECKED_PREFIXES):
        return None
    query = frozenset(k for k, _ in parse_qsl(request.url.query.decode(), keep_blank_values=True))
    try:
        content = request.content
    except httpx.RequestNotRead:  # streamed body (multipart upload): nothing to check
        content = b""
    return Recorded(
        request.method.upper(),
        path.rstrip("/") or "/",
        query,
        body_keys(content, request.headers.get("content-type", "")),
        test,
    )


# --- spec -----------------------------------------------------------------------------------


@cache
def spec_index() -> SpecIndex:
    """The bundled spec, loaded and indexed the way the server's spec tools do it."""
    doc = asyncio.run(bundled("catc_mcp", SPEC_RESOURCE)(None))
    return build_index(doc, source="intent")


@dataclass(frozen=True)
class _Template:
    path: str
    regex: re.Pattern[str]
    literals: int  # literal segments: more is more specific


@cache
def _templates() -> tuple[_Template, ...]:
    seen: dict[str, _Template] = {}
    for op in spec_index().operations:
        p = op.path.rstrip("/") or "/"
        if p in seen:
            continue
        parts = p.strip("/").split("/")
        rx = "/" + "/".join("[^/]+" if re.fullmatch(r"\{[^}]+\}", s) else re.escape(s) for s in parts)
        literals = sum(1 for s in parts if not s.startswith("{"))
        seen[p] = _Template(p, re.compile(rx + "$"), literals)
    return tuple(sorted(seen.values(), key=lambda t: -t.literals))


@cache
def _ops_by_path() -> dict[str, dict[str, Operation]]:
    out: dict[str, dict[str, Operation]] = {}
    for op in spec_index().operations:
        out.setdefault(op.path.rstrip("/") or "/", {})[op.method] = op
    return out


def _schema_fields(name: str | None) -> set[str] | None:
    """Top-level fields of a request schema; None when the spec doesn't describe them."""
    schemas = spec_index().schemas
    seen = 0
    while name and name in schemas and seen < 3:
        sch = schemas[name]
        if sch.get("fields"):
            return set(sch["fields"])
        name, seen = sch.get("items"), seen + 1
    return None


@cache
def match(path: str, method: str) -> tuple[str | None, Operation | None]:
    """(template, operation) for a request path; the most specific template with this method wins."""
    hits = [t for t in _templates() if t.regex.match(path)]
    for t in hits:
        if op := _ops_by_path()[t.path].get(method):
            return t.path, op
    return (hits[0].path if hits else None), None


# --- check ----------------------------------------------------------------------------------


def _allowed(f: Finding, allowlist: Iterable[Allowed]) -> Allowed | None:
    for a in allowlist:
        key = a.key == "*" or re.fullmatch(a.key, f.key) is not None
        same = a.kind == f.kind and a.method in ("*", f.method) and key
        if same and re.fullmatch(a.path, f.path):
            return a
    return None


def check(requests: Iterable[Recorded], allowlist: Iterable[Allowed] = ALLOWLIST) -> Report:
    allowlist = list(allowlist)
    rep = Report()
    found: dict[tuple[str, str, str, str], list[str]] = {}
    for r in requests:
        rep.requests += 1
        template, op = match(r.path, r.method)
        if template is None:
            found.setdefault(("path", r.method, r.path, ""), []).append(r.test)
            continue
        if op is None:
            found.setdefault(("method", r.method, template, ""), []).append(r.test)
            continue
        rep.operations.add((op.method, template))
        declared = {p.name for p in op.params if p.location == "query"}
        for k in sorted(r.query - declared):
            found.setdefault(("query", r.method, template, k), []).append(r.test)
        fields = _schema_fields(op.request)
        if fields is not None:
            for k in sorted(r.body - fields):
                found.setdefault(("body", r.method, template, k), []).append(r.test)
    used: set[int] = set()
    for (kind, method, path, key), tests in sorted(found.items()):
        f = Finding(kind, method, path, key, tuple(sorted({t for t in tests if t})))
        if a := _allowed(f, allowlist):
            rep.allowed.append((f, a))
            used.add(id(a))
        else:
            rep.findings.append(f)
    rep.unused_allowlist = [a for a in allowlist if id(a) not in used]
    return rep
