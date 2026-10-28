"""D130: catc_import_trusted_certificate (respx). Every certificate is generated in the test with
cryptography (a synthetic root, issuing CA and leaf; no lab material). The import request follows the
3.2.2 spec (multipart/form-data, one certFileImport part); its answer (a task) is the Intent API's usual
202 shape, and the duplicate refusal is a synthetic 409/"already exists" (other releases; 3.2.2 answers a
duplicate like a first import, #281). Audit records copy the 3.2.2 wording of a trusted-certificate import
("Successfully imported the certificate from issuer ... with serial number <hex> to Trusted
Certificates", lower-case hex), with synthetic names and ids."""

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import respx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.server import create_server
from catc_mcp.tools import certificates
from catc_mcp.tools.certificates import IMPORT_PATH, fingerprint

from .conftest import make_settings
from .test_write_tools import run

TASK = "11111111-2222-3333-4444-555555555555"
TASK_PATH = f"/dna/intent/api/v1/task/{TASK}"
NOW = datetime.now(UTC)
AUDIT_PATH = "/dna/data/api/v1/event/event-series/audit-logs"


def audit_record(cert: x509.Certificate, *, ms: int | None = None, rid: str = "a1") -> dict[str, Any]:
    name = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    return {
        "instanceId": rid,
        "timestamp": ms if ms is not None else int(datetime.now(UTC).timestamp() * 1000),
        "userId": "mcp-admin",
        "category": "INFO",
        "description": f"Successfully imported the certificate from issuer {issuer} and issued-to {name} "
        f"with serial number {format(cert.serial_number, 'x')} to Trusted Certificates",
    }


@pytest.fixture(autouse=True)
def _fast_readback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(certificates, "READBACK_DELAY", 0)


def audit(api: respx.MockRouter, *answers: list[dict[str, Any]]) -> respx.Route:
    """The audit log: one answer per call (the last repeats); none = always empty."""
    seq = list(answers) or [[]]

    def reply(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=seq.pop(0) if len(seq) > 1 else seq[0])

    return api.get(AUDIT_PATH).mock(side_effect=reply)


def make_cert(
    cn: str,
    *,
    issuer: tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None = None,
    ca: bool = True,
    days: int = 365,
    start: datetime | None = None,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example"),
        ]
    )
    signer_name, signer_key = (issuer[0].subject, issuer[1]) if issuer else (name, key)
    begin = start or NOW - timedelta(days=1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(signer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(begin)
        .not_valid_after(begin + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(signer_key, hashes.SHA256())
    )
    return cert, key


def pem(*certs: x509.Certificate) -> str:
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in certs)


ROOT = make_cert("Example Root CA")
ISSUING = make_cert("Example Issuing CA", issuer=ROOT)
LEAF = make_cert("ise.example.com", issuer=ISSUING, ca=False)


async def flow(args: dict[str, Any], *, apply: bool = True) -> tuple[Any, Any]:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = await run(c, "catc_import_trusted_certificate", args)
        if preview["status"] != "preview" or not apply:
            return preview, None
        done = await run(c, "catc_import_trusted_certificate", {**args, "confirm": preview["confirm"]})
    return preview, done


def task_ok(api: respx.MockRouter) -> respx.Route:
    api.get(TASK_PATH).respond(
        json={"response": {"id": TASK, "progress": "imported", "endTime": 1, "isError": False}}
    )
    return api.post(IMPORT_PATH).respond(
        202, json={"version": "1.0", "response": {"taskId": TASK, "url": f"/api/v1/task/{TASK}"}}
    )


async def test_chain_preview_then_import_root_first(api: respx.MockRouter) -> None:
    post = task_ok(api)
    log = audit(api, [], [], [audit_record(ISSUING[0], rid="a2"), audit_record(ROOT[0], rid="a1")])
    # Given issuing CA first: imported root first.
    preview, done = await flow({"certificate_pem": pem(ISSUING[0], ROOT[0]), "name": "mcp-ca-2026"})
    assert preview["status"] == "preview"
    certs = preview["preview"]["certificates"]
    assert [c["subject"] for c in certs] == [
        "O=Example,CN=Example Root CA",
        "O=Example,CN=Example Issuing CA",
    ]
    assert certs[0]["self_signed"] is True and certs[1]["self_signed"] is False
    assert all(c["ca"] for c in certs)
    assert certs[0]["sha256"] == fingerprint(ROOT[0])
    assert certs[0]["days_left"] in (363, 364)
    assert [c["file"] for c in certs] == ["mcp-ca-2026-1.pem", "mcp-ca-2026-2.pem"]
    assert post.call_count == 2
    first = post.calls[0].request
    assert first.headers["content-type"].startswith("multipart/form-data; boundary=")
    assert b'name="certFileImport"; filename="mcp-ca-2026-1.pem"' in first.content
    assert pem(ROOT[0]).encode() in first.content
    assert pem(ISSUING[0]).encode() in post.calls[1].request.content
    got = done["result"]["certificates"]
    assert [{k: v for k, v in c.items() if k != "read_back"} for c in got] == [
        {"subject": certs[0]["subject"], "sha256": certs[0]["sha256"], "status": "imported", "task_id": TASK},
        {"subject": certs[1]["subject"], "sha256": certs[1]["sha256"], "status": "imported", "task_id": TASK},
    ]
    assert got[0]["read_back"]["serial"] == format(ROOT[0].serial_number, "x")
    assert got[0]["read_back"]["subject"] == "O=Example,CN=Example Root CA"
    assert got[1]["read_back"]["issuer"] == "O=Example,CN=Example Root CA"
    assert got[1]["read_back"]["user"] == "mcp-admin"
    assert "notes" not in done["result"]
    q = log.calls.last.request.url.params
    assert q["description"] == "to Trusted Certificates" and q["isSystemEvents"] == "false"


async def test_single_ca_uses_the_name(api: respx.MockRouter) -> None:
    post = task_ok(api)
    audit(api)
    _, done = await flow({"certificate_pem": pem(ROOT[0]), "name": "mcp-root"})
    assert b'filename="mcp-root.pem"' in post.calls.last.request.content
    assert done["result"]["certificates"][0]["status"] == "imported"


async def test_leaf_is_refused(api: respx.MockRouter) -> None:
    audit(api)
    post = api.post(IMPORT_PATH).respond(202, json={"response": {"taskId": TASK}})
    preview, done = await flow({"certificate_pem": pem(ROOT[0], LEAF[0]), "name": "mcp-x"})
    assert preview["status"] == "blocked" and done is None and not post.called
    assert any("ise.example.com is not a CA certificate" in b for b in preview["blockers"])


async def test_expired_and_future_are_refused(api: respx.MockRouter) -> None:
    audit(api)
    old = make_cert("Old CA", start=NOW - timedelta(days=400), days=30)
    later = make_cert("Later CA", start=NOW + timedelta(days=10))
    preview, _ = await flow({"certificate_pem": pem(old[0], later[0]), "name": "mcp-x"})
    assert preview["status"] == "blocked"
    text = " ".join(preview["blockers"])
    assert "CN=Old CA expired on" in text and "CN=Later CA is not valid until" in text


async def test_duplicate_in_pem_is_refused(api: respx.MockRouter) -> None:
    audit(api)
    preview, _ = await flow({"certificate_pem": pem(ROOT[0], ROOT[0]), "name": "mcp-x"})
    assert preview["status"] == "blocked"
    assert any("in the PEM twice" in b for b in preview["blockers"])


@pytest.mark.parametrize(
    "text",
    [
        "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
        "not a certificate at all",
        "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
    ],
)
async def test_bad_input_is_refused(api: respx.MockRouter, text: str) -> None:
    with pytest.raises(ToolError, match="private key|No PEM certificate|Only CERTIFICATE"):
        await flow({"certificate_pem": text, "name": "mcp-x"})


async def test_key_next_to_cert_is_refused(api: respx.MockRouter) -> None:
    key = (
        ROOT[1]
        .private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        .decode()
    )
    with pytest.raises(ToolError, match="private key"):
        await flow({"certificate_pem": pem(ROOT[0]) + key, "name": "mcp-x"})


async def test_already_trusted_is_reported_and_chain_continues(api: respx.MockRouter) -> None:
    audit(api)
    api.get(TASK_PATH).respond(json={"response": {"id": TASK, "endTime": 1, "isError": False}})
    answers = iter(
        [
            httpx.Response(
                409, json={"response": {"errorCode": "CONFLICT", "message": "Certificate already exists"}}
            ),
            httpx.Response(202, json={"response": {"taskId": TASK}}),
        ]
    )
    post = api.post(IMPORT_PATH).mock(side_effect=lambda _req: next(answers))
    _, done = await flow({"certificate_pem": pem(ROOT[0], ISSUING[0]), "name": "mcp-ca"})
    assert post.call_count == 2
    assert [c["status"] for c in done["result"]["certificates"]] == ["already_trusted", "imported"]


async def test_conflict_without_duplicate_wording_fails(api: respx.MockRouter) -> None:
    audit(api)
    post = api.post(IMPORT_PATH).respond(
        409, json={"response": {"errorCode": "CONFLICT", "message": "Resource is being edited, retry later"}}
    )
    _, done = await flow({"certificate_pem": pem(ROOT[0], ISSUING[0]), "name": "mcp-ca"})
    assert post.call_count == 1
    assert done["result"]["certificates"][0]["status"] == "failed"
    assert "rest of the chain was not sent" in done["result"]["stopped"]


async def test_already_trusted_from_the_task(api: respx.MockRouter) -> None:
    audit(api)
    api.post(IMPORT_PATH).respond(202, json={"response": {"taskId": TASK}})
    api.get(TASK_PATH).respond(
        json={
            "response": {
                "id": TASK,
                "endTime": 1,
                "isError": True,
                "failureReason": "Trusted certificate already present in the truststore",
            }
        }
    )
    _, done = await flow({"certificate_pem": pem(ROOT[0]), "name": "mcp-ca"})
    assert done["result"]["certificates"][0]["status"] == "already_trusted"


async def test_failure_stops_the_chain(api: respx.MockRouter) -> None:
    audit(api)
    post = api.post(IMPORT_PATH).respond(400, json={"response": {"message": "Invalid certificate file"}})
    _, done = await flow({"certificate_pem": pem(ROOT[0], ISSUING[0]), "name": "mcp-ca"})
    res = done["result"]
    assert post.call_count == 1
    assert (
        res["certificates"][0]["status"] == "failed"
        and "Invalid certificate file" in res["certificates"][0]["error"]
    )
    assert "rest of the chain was not sent" in res["stopped"]


async def test_hidden_when_read_only(api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings())) as c:
        assert "catc_import_trusted_certificate" not in {t.name for t in await c.list_tools()}


async def test_duplicate_import_answered_200_is_imported(api: respx.MockRouter) -> None:
    """3.2.2 (#281): re-importing a trusted CA answers like a first import. The preview names the earlier
    import from the audit log, says a re-import is harmless, and the result is `imported`."""
    post = task_ok(api)
    day_ago = int((NOW - timedelta(days=1)).timestamp() * 1000)
    earlier = audit_record(ROOT[0], ms=day_ago, rid="old")
    audit(api, [earlier], [earlier], [audit_record(ROOT[0], rid="new"), earlier])
    preview, done = await flow({"certificate_pem": pem(ROOT[0]), "name": "mcp-root"})
    p = preview["preview"]
    assert "already_trusted" not in p
    assert "neither refuses nor reports a duplicate" in p["duplicates"]
    assert "does no harm" in p["duplicates"]
    assert p["certificates"][0]["imported_before"] == earlier_time(day_ago)
    assert any("was imported before" in n and "mcp-admin" in n for n in p["notes"])
    assert post.call_count == 1
    c = done["result"]["certificates"][0]
    assert c["status"] == "imported"
    # The read-back is the new record, not the earlier one.
    assert c["read_back"]["time"] != earlier_time(day_ago)
    assert c["read_back"]["serial"] == format(ROOT[0].serial_number, "x")


def earlier_time(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")


async def test_missing_audit_entry_is_a_note(api: respx.MockRouter) -> None:
    task_ok(api)
    other = make_cert("Other CA")
    log = audit(api, [], [], [audit_record(other[0])])
    _, done = await flow({"certificate_pem": pem(ROOT[0]), "name": "mcp-root"})
    res = done["result"]
    assert res["certificates"][0]["status"] == "imported"
    assert "read_back" not in res["certificates"][0]
    assert "No audit record of the import yet" in res["notes"][0]
    assert "catc_list_audit_logs" in res["notes"][0]
    # Preview, the re-check at confirm, then every read-back try.
    assert log.call_count == 2 + certificates.READBACK_TRIES


async def test_audit_log_unreadable_is_a_note(api: respx.MockRouter) -> None:
    task_ok(api)
    api.get(AUDIT_PATH).respond(500, json={"response": {"message": "internal error"}})
    preview, done = await flow({"certificate_pem": pem(ROOT[0]), "name": "mcp-root"})
    assert preview["status"] == "preview"
    assert "earlier imports not checked" in preview["preview"]["notes"][0]
    res = done["result"]
    assert res["certificates"][0]["status"] == "imported"
    assert "not readable for the read-back" in res["notes"][0]


async def test_serial_match_ignores_case_colons_and_zeros() -> None:
    assert certificates.serial_key("00:0A:bC") == certificates.serial_key("abc") == "abc"
    m = certificates.AUDIT_IMPORT_RE.search(
        "Successfully imported the certificate from issuer CN=Example CA, DC=example, DC=com and issued-to "
        "CN=Example CA, DC=example, DC=com with serial number 1a2b3c4d to Trusted Certificates"
    )
    assert m and m["serial"] == "1a2b3c4d" and m["subject"] == "CN=Example CA, DC=example, DC=com"
