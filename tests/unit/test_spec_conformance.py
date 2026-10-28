"""D52: the spec-conformance checker itself (the recorder runs it over the whole suite at session end)."""

import httpx

from .spec_allowlist import ALLOWLIST, Allowed
from .spec_conformance import Recorded, check, match, record

DEV = "/dna/intent/api/v1/network-device"


def test_conforming_request_has_no_findings() -> None:
    rep = check([Recorded("GET", DEV, frozenset({"hostname", "offset", "limit"}))], ())
    assert rep.findings == [] and rep.requests == 1
    assert ("GET", DEV) in rep.operations


def test_most_specific_template_wins() -> None:
    assert match(f"{DEV}/count", "GET")[0] == f"{DEV}/count"
    assert match(f"{DEV}/abc-123", "GET")[0] == f"{DEV}/{{id}}"


def test_unknown_path_method_query_and_body_are_reported() -> None:
    rep = check(
        [
            Recorded("GET", "/dna/intent/api/v1/no-such-thing", test="t::a"),
            Recorded("PATCH", DEV, test="t::b"),
            Recorded("GET", DEV, frozenset({"bogusKey"}), test="t::c"),
            Recorded("POST", "/dna/intent/api/v1/tag", body=frozenset({"name", "bogusField"}), test="t::d"),
        ],
        (),
    )
    got = {(f.kind, f.key) for f in rep.findings}
    assert got == {("path", ""), ("method", ""), ("query", "bogusKey"), ("body", "bogusField")}
    assert all(f.tests for f in rep.findings)
    assert "bogusField" in rep.text()


def test_allowlist_entries_have_reasons_and_suppress_their_findings() -> None:
    assert all(a.reason.strip() for a in ALLOWLIST)
    rep = check(
        [
            Recorded("GET", "/dna/platform/management/business-api/v1/execution-status/e1"),
            Recorded("POST", "/api/v1/siteprofile"),
            Recorded("POST", "/dna/intent/api/v1/tag/t1/member", body=frozenset({"networkdevice"})),
        ]
    )
    assert rep.findings == [] and len(rep.allowed) == 3


def test_allowlist_is_scoped_to_its_key() -> None:
    only = (Allowed("query", "GET", DEV, "other", "x"),)
    rep = check([Recorded("GET", DEV, frozenset({"bogusKey"}))], only)
    assert [f.key for f in rep.findings] == ["bogusKey"] and rep.unused_allowlist == list(only)


def test_record_reads_query_and_json_body_keys() -> None:
    req = httpx.Request(
        "POST",
        "https://catc.test/dna/intent/api/v1/tag/",
        params={"a": "1", "b": ""},
        json=[{"x": 1}, {"y": 2}],
    )
    r = record(req, "t")
    assert r is not None and r.path == "/dna/intent/api/v1/tag"
    assert r.query == {"a", "b"} and r.body == {"x", "y"}
    assert record(httpx.Request("GET", "https://catc.test/elsewhere")) is None
