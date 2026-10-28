"""Trusted certificates (roadmap D130): put an enterprise CA chain into Catalyst Center's trust store.

`catc_import_trusted_certificate` sends each CA certificate of a PEM chain to
POST /dna/intent/api/v1/trustedCertificates/import (multipart/form-data, one `certFileImport` file part,
as the 3.2.2 spec describes it). The preview parses every certificate locally (subject, issuer,
validity, CA flag, SHA-256 fingerprint) and refuses leaves, expired or not-yet-valid certificates and
anything carrying a private key, so only a CA chain reaches the appliance.

The public API has no read of the trust store (no GET next to the import on 3.2.2), so the preview cannot
say beforehand whether a certificate is already trusted. Catalyst Center refuses a duplicate import; the
result reports that certificate as `already_trusted` instead of failing, and goes on with the rest of
the chain. The system (server) certificate import (POST /certificate, /certificate-p12) is out of scope:
it restarts controller services.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import re
from datetime import UTC, datetime
from typing import Annotated, Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastmcp import Context
from pydantic import Field

from catc_mcp._core import Confirm, InvalidRequest, Plan, ToolRegistrar, get_client, preview_or_apply
from catc_mcp._core.errors import UpstreamError
from catc_mcp.client import CatcApp

IMPORT_PATH = "/dna/intent/api/v1/trustedCertificates/import"
MAX_CHAIN = 10
# How Catalyst Center words a refused duplicate (matched case-insensitively in the error or task text).
DUPLICATE_RE = re.compile(r"already\s+(exists?|present|imported|trusted)|duplicate", re.IGNORECASE)
PEM_BLOCK_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----")


def _name(n: x509.Name) -> str:
    return n.rfc4514_string() or "(empty)"


def _iso(d: datetime) -> str:
    return d.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()


def describe(cert: x509.Certificate, now: datetime) -> tuple[dict[str, Any], list[str]]:
    """(row, problems) for one certificate: what the preview shows and why it can't be imported."""
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca: bool = bc.ca
        path_len = bc.path_length
    except x509.ExtensionNotFound:
        is_ca, path_len = False, None
    start, end = cert.not_valid_before_utc, cert.not_valid_after_utc
    subject, issuer = _name(cert.subject), _name(cert.issuer)
    row: dict[str, Any] = {
        "subject": subject,
        "issuer": issuer,
        "self_signed": cert.subject == cert.issuer,
        "ca": is_ca,
        "not_before": _iso(start),
        "not_after": _iso(end),
        "days_left": (end - now).days,
        "serial": format(cert.serial_number, "X"),
        "sha256": fingerprint(cert),
    }
    if path_len is not None:
        row["path_length"] = path_len
    problems: list[str] = []
    if not is_ca:
        problems.append(
            f"{subject} is not a CA certificate (no basicConstraints CA:TRUE): the trust store takes the "
            "issuing and root CAs, not a leaf."
        )
    if end <= now:
        problems.append(f"{subject} expired on {_iso(end)}.")
    elif start > now:
        problems.append(f"{subject} is not valid until {_iso(start)}.")
    return row, problems


def parse_chain(pem: str) -> list[x509.Certificate]:
    """The certificates of a PEM text, in the order given. Refuses keys and anything but certificates."""
    labels = set(PEM_BLOCK_RE.findall(pem))
    if any("PRIVATE KEY" in label for label in labels):
        raise InvalidRequest("The PEM contains a private key: send only the CA certificate(s).")
    if not labels:
        raise InvalidRequest("No PEM certificate found (expected '-----BEGIN CERTIFICATE-----').")
    if labels - {"CERTIFICATE"}:
        raise InvalidRequest(f"Only CERTIFICATE blocks are accepted (found {', '.join(sorted(labels))}).")
    try:
        certs = x509.load_pem_x509_certificates(pem.encode())
    except ValueError as e:
        raise InvalidRequest(f"Not a valid PEM certificate: {str(e)[:200]}") from e
    if len(certs) > MAX_CHAIN:
        raise InvalidRequest(f"At most {MAX_CHAIN} certificates per import (got {len(certs)}).")
    return certs


def root_first(certs: list[x509.Certificate]) -> list[x509.Certificate]:
    """Issuers before the certificates they signed (a self-signed root first), so each certificate's
    issuer is already trusted when it arrives; certificates of unrelated chains keep their order."""
    out: list[x509.Certificate] = []
    left = list(certs)
    while left:
        names = {c.subject for c in left}
        ready = [c for c in left if c.subject == c.issuer or c.issuer not in names]
        pick = ready[0] if ready else left[0]
        out.append(pick)
        left.remove(pick)
    return out


def multipart(filename: str, data: bytes) -> tuple[bytes, str]:
    """(body, content-type) of a multipart/form-data request with one certFileImport file part."""
    req = httpx.Request(
        "POST",
        "https://placeholder.invalid/",
        files={"certFileImport": (filename, data, "application/x-pem-file")},
    )
    return req.read(), req.headers["content-type"]


def is_duplicate(err: Exception) -> bool:
    """A refused duplicate, by its wording. A bare 409 is not enough: the 3.2.2 spec also uses 409 for an
    edit conflict that may succeed on retry, and calling that already_trusted would hide a missing CA."""
    return bool(DUPLICATE_RE.search(str(err)))


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Import a trusted CA certificate")
    async def catc_import_trusted_certificate(
        ctx: Context,
        certificate_pem: Annotated[
            str,
            Field(
                min_length=20,
                max_length=200_000,
                description="The CA certificate, or the CA chain (issuing CA and root), as PEM. "
                "Certificates only: no private key.",
            ),
        ],
        name: Annotated[
            str,
            Field(
                min_length=1,
                max_length=64,
                pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
                description="File name stem the certificates are uploaded as (letters, digits, '.', '_', "
                "'-'), e.g. 'mcp-issuing-ca-2026'; the trust store lists them by subject",
            ),
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add an enterprise CA certificate, or a CA chain, to Catalyst Center's trusted certificates, so
        it trusts the servers and clients that CA issued (ISE's admin and pxGrid certificates, a syslog or
        proxy server). Do it when an issuing CA is renewed or replaced, before the leaves are re-issued,
        or the ISE integration breaks when they roll. Preview-first: the preview shows each certificate
        (subject, issuer, validity, days left, CA flag, SHA-256 fingerprint) in the order it is imported
        (root first) and refuses leaf, expired and not-yet-valid certificates. The trust store has no read
        over the API: a certificate already trusted is reported as already_trusted in the result. The
        system (server) certificate is not changed by this tool."""
        app: CatcApp = get_client(ctx)
        now = datetime.now(UTC)
        certs = root_first(parse_chain(certificate_pem))
        rows: list[dict[str, Any]] = []
        blockers: list[str] = []
        for c in certs:
            row, problems = describe(c, now)
            rows.append(row)
            blockers += problems
        seen: set[str] = set()
        for r in rows:
            if r["sha256"] in seen:
                blockers.append(f"{r['subject']} is in the PEM twice.")
            seen.add(r["sha256"])
        files = [f"{name}.pem" if len(certs) == 1 else f"{name}-{i + 1}.pem" for i in range(len(certs))]
        plan = Plan(
            f"Import {len(certs)} trusted CA certificate(s) into Catalyst Center: "
            + "; ".join(r["subject"] for r in rows),
            details={
                "certificates": [{**r, "file": f} for r, f in zip(rows, files, strict=True)],
                "method": "POST",
                "path": IMPORT_PATH,
                "body": "multipart/form-data, one certFileImport part per certificate (PEM)",
                "already_trusted": "not readable over the API: a duplicate is reported in the result",
            },
            side_effects=[
                "Catalyst Center trusts certificates these CAs issue (TLS to ISE, pxGrid, syslog, proxy).",
                "Nothing changes on the network devices or on Catalyst Center's own server certificate.",
                "Undo: remove the certificate under System > Settings > Certificates > Trusted Certificates "
                "(no API for it on 3.2.2).",
            ],
            fingerprint=[r["sha256"] for r in rows],
            blockers=blockers,
        )

        async def apply() -> Any:
            results: list[dict[str, Any]] = []
            for c, r, f in zip(certs, rows, files, strict=True):
                body, ctype = multipart(f, c.public_bytes(serialization.Encoding.PEM))
                one: dict[str, Any] = {"subject": r["subject"], "sha256": r["sha256"]}
                try:
                    sent = await app.api.request(
                        "POST", IMPORT_PATH, content=body, headers={"Content-Type": ctype}
                    )
                    done = await app.wait_job(sent, ctx=ctx, what="trusted certificate import")
                    one["status"] = "imported"
                    if done.get("task_id"):
                        one["task_id"] = done["task_id"]
                except UpstreamError as err:
                    if not is_duplicate(err):
                        results.append({**one, "status": "failed", "error": str(err)[:300]})
                        return {
                            "certificates": results,
                            "stopped": f"Import failed at {r['subject']}; the rest of the chain "
                            "was not sent.",
                        }
                    one["status"] = "already_trusted"
                results.append(one)
            return {"certificates": results}

        return await preview_or_apply(
            ctx,
            tool="catc_import_trusted_certificate",
            args={"certificate_pem": certificate_pem, "name": name},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
