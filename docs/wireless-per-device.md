# Wireless per-device configuration (D71 research)

Researched 2026-10-18 against the bundled 3.2.2 spec, the live Catalyst Center 3.2.2-75131 (read-only
calls), the Catalyst Center 3.1.x user guide (Provision Wireless Devices > Per-Device Configuration) and
Cisco Live BRKOPS-2416 (EMEA 2026).

## Two different things are called "feature templates"

| | Wireless feature templates ("model config") | Per-device configuration |
|---|---|---|
| API | `/dna/intent/api/v1/featureTemplates/wireless/*` | `/dna/campus/api/v1/wirelessControllers/{id}/intended/*`, `.../deployed/*`, `.../intended/deploy`, `.../intended/deviceDeployments` |
| What | Design objects: Advanced SSID, AAA RADIUS attributes, CleanAir, 802.11ax, 802.11be status, event-driven RRM, FlexConnect, multicast, RRM FRA, RRM general | One model per 9800 feature: WLAN, policy, RLAN profiles, policy/site/RF tags, RF/radio profiles, AP join, flex, mDNS, tag mappings... |
| How it reaches a WLC | Listed in a wireless network profile (`wirelessProfiles[].featureTemplates`) and pushed by `POST /wirelessControllers/{id}/provision` (overrides: `featureTemplatesOverridenAttributes`); status `modelConfigProvisionStatus` in `provisionStatus` | Edit the intended model (`.../intended/<group>/update` or per-record POST/PUT/DELETE), then `POST .../intended/deploy`; status from `.../intended/deviceDeployments?deployActivityId=` |
| Works with site-based profiles | Yes: it is an add-on to them | No: read-only at best |
| Covers SSID security, VLAN, RF profile | No | Yes: `ssids/wlanProfiles` (security), `ssids/policyProfiles` (VLAN), `radioFrequencies/rfProfiles` |

The lab CatC has only the system (default) feature templates (`featureTemplates/wireless/summary`), and the
lab WLC reports `modelConfigProvisionStatus: NOT_STARTED`.

So D71's three features (SSID security, VLAN mapping, RF profile) can only be written through the
per-device models; `featureTemplates/wireless/*` has none of them.

## How a 9800 becomes per-device

- Off by default, per WLC. GUI only: Provision > Inventory > the WLC > View Device Details > **Enable
  Per-Device Configuration** > Enable, then resync the WLC. The 3.2.2 spec has no API for this step.
- Enabling pushes nothing: Catalyst Center learns the WLC's running config into the models (BRKOPS-2416).
- Needs IOS XE 17.12 or later (`GET /dna/campus/api/v1/wirelessControllers/supported/deviceVersions`
  lists 17.12-17.18 and 26.01 on this CatC; the lab 9800-CL runs 17.18.2).
- Read-write only for a WLC that is greenfield (never provisioned) or assurance-only. A WLC provisioned
  with site-based network profiles ("intent mode") gets per-device configuration **read-only**; until it is
  enabled the models answer 404 NCWS70003 "provisioned via Site-based Network profiles" (what the lab
  WLC answers today). Not supported for SD-Access wireless.

## Can it be reversed?

Neither the guide nor the spec has a disable or revert step, and there is no API for it. A WLC
provisioned through site-based profiles can't be made read-write either: the only route is deleting it
from the inventory and adding it again unprovisioned, which drops its site-based provisioning state.
Treat both directions as one-way per WLC.

## Deploy prerequisite

`POST .../intended/deploy` "can be used only if the provisioning settings do not require Preview or ITSM
Approval". This CatC has `GET /dna/intent/api/v1/provisioningSettings` = `requirePreview: true`. That
setting is global: it covers every provisioning flow on the controller.

## Lab state (read-only checks)

- mcp-catc-wlc (510abd1b-24be-4e2d-9498-c804297c6e85, 198.18.128.173, C9800-CL 17.18.2) at
  Global/mcp-test-lab/mcp-test-bldg; `networkIntentProvisionStatus: SUCCESS` (D14, site-based).
- `intended/deviceDeployments` answers for it (the config groups D14's provisioning deployed), even
  though the feature models don't.
- No wireless network profiles exist now (`GET /wirelessProfiles` is empty).
