# Wireless per-device configuration (D71)

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

## Live results (2026-10-18, second 9800-CL)

`mcp-catc-wlc2` (198.18.128.174, C9800-CL 17.18.2) was discovered, assigned to
Global/mcp-test-lab/mcp-test-bldg and never provisioned. The owner then enabled Per-Device Configuration in
the GUI and the WLC was resynced. All writes went through this branch's server over local HTTP, preview and
confirm as separate calls.

What Catalyst Center 3.2.2 does:

- **Before enabling**, the models answer `400 NCWS70003 "Per-device configuration is not enabled for this
  device"` (a site-based WLC answers 404 with "Site-based Network profiles"). `catc_get_wlc_config` reports
  both cleanly.
- **Enabling learns, it doesn't copy.** The WLC's running config (9800 defaults here: 7 RF profiles,
  default policy profile and tags...) lands in the *deployed* model only; the *intended* model stays empty
  until something is staged. The set tools therefore look in deployed when intended lacks a record, and a
  MERGE on such a learned record sends the whole learned record (secrets aside) plus the change, so the
  intended record is complete, never sparse.
- **Once anything is staged**, an intended family with no records answers `500 NCND00050` instead of an
  empty list (its `/count` too). Deployed reads don't. The tools read that as "no records".
- **Deploy pushes the intended changes and leaves records it never had** (the learned defaults survived
  every deploy). **Removing an intended record is a delete on the WLC** at the next deploy, and the
  intended-vs-deployed diff can't show that pending delete. There is no discard API: putting the record back
  in intended exactly as deployed cleared it (the next deploy succeeded).
- **The deploy task returns when it is scheduled**; its task id is the activity that `deviceDeployments`
  reports as `deployActivityId` (the spec says `activityId`). Each deploy is one config group
  `LDI_<device id>` whose version goes up by one per deploy.
- **A push the WLC refuses is rolled back as a whole** (`Rollback Success`, with the WLC's message in
  `error`). Seen: "PreConfigured rf profile can not be updated" (and "...deleted"), and "FT Adaptive is not
  allowed when both WPA2 and WPA3 are enabled". The tools now refuse the 9800's pre-configured RF profiles
  and turn adaptive 802.11r off for WPA3 modes. `catc_deploy_wlc_config` reports `outcome: failed` then.
- URWB models answer `403 NCWS70003` ("URWB is currently in beta"): reported as not enabled.
- Assigning the WLC to a site deployed Catalyst Center's own config groups (DNS, syslog, SNMP trap,
  telemetry, certificates), visible in `catc_get_wlc_deployments`. No WLAN config.

Proof (WLC CLI, then `catc_get_wlc_config`):

| Change | Tool | On the WLC |
|---|---|---|
| WLAN `mcp-d71` + policy `mcp-d71-policy` + tag `mcp-d71-tag` (setup) | `catc_api_call` (intended `ssids/update`, CREATE) + deploy | `17 mcp-d71-wlan mcp-d71 UP [WPA2][PSK][AES]`; tag maps WLAN to policy |
| SSID `mcp-d71` VLAN 1 -> 20 (through the policy tag) | `catc_set_wlan_vlan` + `catc_deploy_wlc_config` | `wireless profile policy mcp-d71-policy` / `vlan 20` / `no shutdown`; intended 20, deployed 20, diff in sync |
| Learned `default-policy-profile` VLAN 1 -> 30 | `catc_set_wlan_vlan` + deploy | `vlan 30`; description and DISABLED state kept |
| `mcp-d71` WPA2 -> WPA2/WPA3 transition | `catc_set_wlan_security` + deploy | `[WPA2 + WPA3][PSK][SAE][AES]`, `security pmf optional`, `no security ft adaptive` |
| Pre-configured RF profile description | `catc_set_rf_profile` + deploy | refused by the WLC and rolled back (now refused by the tool) |

`requirePreview` was turned off for the proof and restored afterwards (each flip previewed); with it back
on, the deploy preview is blocked again.
