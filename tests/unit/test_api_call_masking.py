"""catc_api_call writes: secrets in the body are masked in the preview, the result and the audit log, and
sent unmasked on confirm (core v0.14.2; live on 2026-10-18 a WLC intended-SSID update showed the PSK)."""

import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp._core.formatting import MASK
from catc_mcp.server import create_server

from .conftest import make_settings
from .test_write_tools import run

WLC_ID = "5b6d9c1e-2f3a-4b5c-8d9e-0f1a2b3c4d5e"
PATH = f"/dna/campus/api/v1/wirelessControllers/{WLC_ID}/intended/ssids/update"
PSK, RADIUS, COMMUNITY = "Lab-PSK-9f3k2", "Rad-Secret-7q1", "Comm-RO-4x8"
SECRETS = (PSK, RADIUS, COMMUNITY)
BODY: dict[str, Any] = {
    "ssids": [
        {
            "ssid": "corp",
            "authType": "WPA2_PERSONAL",
            "passphrase": PSK,
            "aaa": {"servers": [{"address": "10.0.0.5", "sharedSecret": RADIUS}]},
        }
    ],
    "snmp": {"roCommunity": COMMUNITY},
}


@pytest.fixture
def audit_lines() -> Iterator[list[str]]:
    """Every audit record, captured on the audit logger itself (it doesn't propagate to caplog)."""
    lines: list[str] = []

    class Grab(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append(record.getMessage())

    logger = logging.getLogger("stutters_mcp_core.audit")
    handler, level = Grab(), logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    yield lines
    logger.removeHandler(handler)
    logger.setLevel(level)


def leaked(value: Any) -> list[str]:
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return [s for s in SECRETS if s in text]


async def test_api_call_masks_body_secrets_and_sends_them_unmasked(
    api: respx.MockRouter, audit_lines: list[str]
) -> None:
    route = api.post(PATH).respond(json={"response": {"taskId": "t-1", "echo": BODY}})
    args = {"method": "POST", "path": PATH, "body": BODY}
    async with Client(create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))) as c:
        preview = await run(c, "catc_api_call", args)
        assert preview["status"] == "preview" and not route.called
        shown = preview["preview"]["body"]
        assert not leaked(preview)
        ssid = shown["ssids"][0]
        assert ssid["passphrase"] == MASK and ssid["aaa"]["servers"][0]["sharedSecret"] == MASK
        assert shown["snmp"]["roCommunity"] == MASK
        # Non-secret fields are shown as given.
        assert ssid["ssid"] == "corp" and ssid["aaa"]["servers"][0]["address"] == "10.0.0.5"

        done = await run(c, "catc_api_call", {**args, "confirm": preview["confirm"]})

    assert done["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.content) == BODY  # masking never changes what is sent
    assert not leaked(done)  # the appliance's echo of the body is masked too
    assert done["result"]["response"]["echo"]["ssids"][0]["passphrase"] == MASK
    assert any('"catc_api_call"' in line for line in audit_lines)  # the audit check below is not vacuous
    assert not leaked("\n".join(audit_lines))


async def test_api_call_token_is_bound_to_the_real_body(api: respx.MockRouter) -> None:
    """The preview shows the mask, but the token binds the real value: a different PSK needs a new preview."""
    route = api.post(PATH).respond(json={"response": {"taskId": "t-1"}})
    args = {"method": "POST", "path": PATH, "body": BODY}
    other = json.loads(json.dumps(BODY))
    other["ssids"][0]["passphrase"] = "Another-PSK-5m2"
    async with Client(create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))) as c:
        preview = await run(c, "catc_api_call", args)
        assert preview["preview"] == (await run(c, "catc_api_call", {**args, "body": other}))["preview"]
        with pytest.raises(ToolError, match="arguments differ"):
            await run(c, "catc_api_call", {**args, "body": other, "confirm": preview["confirm"]})
    assert not route.called


async def test_api_call_masks_wlc_only_secret_keys(api: respx.MockRouter) -> None:
    """Core 0.14.3: `WLC_SECRET_KEYS` (names the core's secret pattern misses) are registered in
    `EXTRA_SECRET_KEYS` at import time, so a raw catc_api_call preview masks them too."""
    body = {
        "ntpServers": [{"address": "10.0.0.9", "ntpServerTrustKey": "Trust-Key-3v9"}],
        "wep": {"keyIndex": 1, "wepKey": "Wep-Key-8p2"},
        "spaces": {"spacesConnCfgToken": "Spaces-Tok-1z4"},
    }
    api.post(PATH).respond(json={"response": {"taskId": "t-2"}})
    async with Client(create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))) as c:
        preview = await run(c, "catc_api_call", {"method": "POST", "path": PATH, "body": body})
    shown = preview["preview"]["body"]
    assert shown["ntpServers"][0]["ntpServerTrustKey"] == MASK
    assert shown["wep"]["wepKey"] == MASK and shown["wep"]["keyIndex"] == 1
    assert shown["spaces"]["spacesConnCfgToken"] == MASK
    for secret in ("Trust-Key-3v9", "Wep-Key-8p2", "Spaces-Tok-1z4"):
        assert secret not in json.dumps(preview)
