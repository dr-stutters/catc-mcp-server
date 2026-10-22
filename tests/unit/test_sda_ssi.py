"""D107: Security Service Insertion readiness (respx). The empty list and the 403 are the 3.2.2 lab
appliance's live answers (2026-10-21, no fabric yet; a role without Security.SSI); rated rows follow the
spec."""

import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp import rbac

from .test_read_tools import AREA, BLDG, GLOBAL, call
from .test_sda import FABRIC
from .test_write_tools import mock_sites

BASE = "/dna/intent/api/v1/securityServiceInsertion/fabricSitesReadiness"


async def test_sites_and_empty(api: respx.MockRouter) -> None:
    api.get(BASE).respond(json={"response": [], "version": "1.0"})
    out = await call("catc_get_ssi_readiness")
    assert out["fabric_sites"] == [] and "No fabric sites rated" in out["note"]


async def test_vn_and_devices(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get(f"/dna/intent/api/v1/sites/{BLDG['id']}").respond(json={"response": BLDG})
    api.get("/dna/intent/api/v1/sda/fabricSites").respond(json={"response": [FABRIC]})
    api.get(f"{BASE}/{FABRIC['id']}").respond(
        json={
            "response": [
                {
                    "id": "vn-uuid-1",
                    "layer3VirtualNetworkId": 4099,  # an integer: not the id the device path takes
                    "virtualNetworkName": "MCP_VN",
                    "readiness": "Ready",
                    "readyDeviceCount": 2,
                    "totalDeviceCount": 2,
                }
            ]
        }
    )
    dev = api.get(f"{BASE}/{FABRIC['id']}/virtualNetworks/vn-uuid-1").respond(
        json={
            "response": [
                {"hostName": "mcp-catc-fab-bcp", "fabricRoles": ["BORDER_NODE"], "readiness": "Ready"}
            ]
        }
    )
    out = await call(
        "catc_get_ssi_readiness", {"fabric_site": "Global/AU/SYD-1", "virtual_network": "MCP_VN"}
    )
    assert out["virtual_networks"][0]["readiness"] == "Ready" and dev.called
    assert out["devices"][0]["hostName"] == "mcp-catc-fab-bcp"
    with pytest.raises(ToolError, match="NOPE is not rated"):
        await call("catc_get_ssi_readiness", {"fabric_site": "Global/AU/SYD-1", "virtual_network": "NOPE"})


async def test_403_names_the_permission(api: respx.MockRouter) -> None:
    api.get(BASE).respond(403, json={"message": "Role does not have valid permissions to access the API"})
    with pytest.raises(ToolError, match="Security.SSI Read") as err:
        await call("catc_get_ssi_readiness")
    # live 2026-10-21: a custom role with Security.SSI Read still gets 403; SUPER-ADMIN-ROLE reads it
    assert "SUPER-ADMIN-ROLE" in str(err.value)
    assert rbac.READ["Security.SSI"] == "Read"
