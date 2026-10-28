"""D130: catc_import_trusted_certificate (respx). Every certificate is generated in the test with
cryptography (a synthetic root, issuing CA and leaf; no lab material). The import request follows the
3.2.2 spec (multipart/form-data, one certFileImport part); its answer (a task) is the Intent API's usual
202 shape, and the duplicate refusal is a synthetic 409/"already exists"."""

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
from catc_mcp.tools.certificates import IMPORT_PATH, fingerprint

from .conftest import make_settings
from .test_write_tools import run

TASK = "11111111-2222-3333-4444-555555555555"
TASK_PATH = f"/dna/intent/api/v1/task/{TASK}"
NOW = datetime.now(UTC)


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
    assert done["result"]["certificates"] == [
        {"subject": certs[0]["subject"], "sha256": certs[0]["sha256"], "status": "imported", "task_id": TASK},
        {"subject": certs[1]["subject"], "sha256": certs[1]["sha256"], "status": "imported", "task_id": TASK},
    ]


async def test_single_ca_uses_the_name(api: respx.MockRouter) -> None:
    post = task_ok(api)
    _, done = await flow({"certificate_pem": pem(ROOT[0]), "name": "mcp-root"})
    assert b'filename="mcp-root.pem"' in post.calls.last.request.content
    assert done["result"]["certificates"][0]["status"] == "imported"


async def test_leaf_is_refused(api: respx.MockRouter) -> None:
    post = api.post(IMPORT_PATH).respond(202, json={"response": {"taskId": TASK}})
    preview, done = await flow({"certificate_pem": pem(ROOT[0], LEAF[0]), "name": "mcp-x"})
    assert preview["status"] == "blocked" and done is None and not post.called
    assert any("ise.example.com is not a CA certificate" in b for b in preview["blockers"])


async def test_expired_and_future_are_refused(api: respx.MockRouter) -> None:
    old = make_cert("Old CA", start=NOW - timedelta(days=400), days=30)
    later = make_cert("Later CA", start=NOW + timedelta(days=10))
    preview, _ = await flow({"certificate_pem": pem(old[0], later[0]), "name": "mcp-x"})
    assert preview["status"] == "blocked"
    text = " ".join(preview["blockers"])
    assert "CN=Old CA expired on" in text and "CN=Later CA is not valid until" in text


async def test_duplicate_in_pem_is_refused(api: respx.MockRouter) -> None:
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


async def test_already_trusted_from_the_task(api: respx.MockRouter) -> None:
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
