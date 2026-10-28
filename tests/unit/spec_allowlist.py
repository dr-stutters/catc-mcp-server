"""D52: requests the tools make on purpose that the bundled catc-3.2.2 spec doesn't describe.

Every entry needs a reason. `path` is a regex matched against the request path (unmatched paths)
or the spec template (method/query/body findings); `key` is a regex matched against the query or
body key, or '*' for any key. Name the keys: '*' on a query/body entry hides drift on that operation.
Add an entry only when the live appliance is known to accept the request (cite the proof).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Allowed:
    kind: str  # path | method | query | body
    method: str  # HTTP method or '*'
    path: str  # regex
    key: str = "*"  # regex, or '*'
    reason: str = ""


ALLOWLIST: tuple[Allowed, ...] = (
    Allowed(
        "path",
        "GET",
        r"/dna/platform/management/business-api/v1/execution-status/[^/]+",
        reason="Async business-API calls (202 + executionStatusUrl) are polled here; the endpoint is "
        "platform-level and not part of the Intent API spec export (proven live on 3.2.2).",
    ),
    Allowed(
        "path",
        "*",
        r"/api/v1/siteprofile(/.*)?",
        reason="The UI's internal network-profile API: the switching-profile fallback when the SDA "
        "package (and its documented API) is absent. Internal, so never in the spec.",
    ),
    Allowed(
        "body",
        "POST",
        r"/dna/intent/api/v1/tag/\{id\}/member",
        reason="The spec's TagMemberDTO schema is wrong for adding members: the appliance takes "
        "{'<memberType>': [ids]} (e.g. 'networkdevice'), proven live on 3.2.2.",
    ),
    Allowed(
        "query",
        "GET",
        r"/dna/campus/api/v1/wirelessControllers/\{networkDeviceId\}/(intended|deployed)/ssids/"
        r"(policyTags/\{policyTagId\}/policyTag(Wlan|Rlan)Policies|"
        r"wlanProfiles/\{wlanProfileId\}/(mpskKeyConfigs|radioPolicyConfigs))",
        key="offset|limit",
        reason="catc_get_wlc_config(children=true) pages every feature model with offset/limit, the "
        "sub-collections too; the spec leaves both off these four, the appliance accepts them (children=true "
        "read with no error on 3.2.2 and a 17.18 WLC, 2026-10-28).",
    ),
    Allowed(
        "body",
        "POST",
        r"/dna/campus/api/v1/wirelessControllers/\{networkDeviceId\}/intended/ssids/update",
        key="ssids|snmp",
        reason="test_api_call_masking sends a synthetic body through catc_api_call (caller-supplied, "
        "not a curated tool's request) to prove secrets are masked; the curated tools send wlanProfiles.",
    ),
)
