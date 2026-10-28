# Wired per-device configuration (D125)

Catalyst Center 3.1+/3.2 keeps an **intended** layer-2 model per switch once Per Device Configuration (PDC) is
enabled on it, the wired twin of the 9800 flow in [wireless-per-device.md](wireless-per-device.md). Built
2026-10-28 against the bundled 3.2.2 spec; reads checked on the lab 3.2.2-75131 (PDC off).

| Tool | Tier | Requests |
|---|---|---|
| `catc_get_wired_config` | read | `GET .../configFeatures/supported/layer2`, `GET .../intended/layer2/{feature}`, `GET .../deployed/layer2/{feature}` |
| `catc_set_wired_feature` | write | `POST` (first intent for a feature), `PUT` (update) or `DELETE` on `.../intended/layer2/{feature}` |
| `catc_deploy_wired_config` | dangerous | `POST .../intended/configurationModels`, `POST` + `GET .../configurationModels/{previewActivityId}/config`, `POST .../configurationModels/{previewActivityId}/deploy` or `DELETE .../configurationModels/{previewActivityId}`; status from `GET .../intended/deviceDeployments?deployActivityId=` |

All paths are under `/dna/intent/api/v1/wired/networkDevices/{id}`.

## Before you start: enable PDC (GUI only)

Until PDC is on, every model read answers `400 NCCO15475 "Per Device Configuration (PDC) must be enabled on
the device"` (seen live on 3.2.2). The tools turn that into "enable PDC in Inventory first". There is no API
for the toggle in 3.2.2: enable it in the switch's device details in the Inventory. Enabling pushes nothing;
Catalyst Center learns the running layer-2 config into the deployed model, and the intended model starts
empty (it holds only what is changed through Catalyst Center).

`GET .../intended/deviceDeployments` answers without PDC: it lists every config group Catalyst Center pushed
to the switch (syslog, SNMP traps, telemetry, certificates, CTS...).

## Features and items

`supported/layer2` names the features the switch takes (the 3.2.2 schemas: `vlanConfig`, `stpGlobalConfig`,
`stpInterfaceConfig`, `vtpGlobalConfig`, `vtpInterfaceConfig`, `cdpGlobalConfig`, `cdpInterfaceConfig`,
`lldpGlobalConfig`, `lldpInterfaceConfig`, `dhcpSnoopingGlobalConfig`, `dhcpSnoopingInterfaceConfig`,
`igmpSnoopingGlobalConfig`, `mldSnoopingGlobalConfig`, `dot1xGlobalConfig`, `dot1xInterfaceConfig`,
`mabInterfaceConfig`, `switchportInterfaceConfig`, `trunkInterfaceConfig`, `portChannelConfig`). A feature
body is `{"<feature>": {"items": [...]}}`; each item carries a `configType` (filled in by the tool). Items are
keyed by `vlanId` (VLANs), `interfaceName` (the interface features) or are the one global record.

`catc_set_wired_feature` modes:

- `merge` (default): the given fields go into the intended item. An item only in the deployed model (learned
  from the switch) is taken whole as the base, so the intent never becomes a sparse record.
- `replace`: the given items are the feature's whole intent.
- `remove`: these items leave the intent (the last one deletes the feature intent).
- `delete`: the whole feature intent goes.

Deploy is **additive** (spec): configuration the intent doesn't name stays on the switch. Whether taking an
item out of the intent sends a `no` command is shown by the deploy's CLI preview.

## Deploy with a CLI preview

The deploy preview builds a configuration model, generates the device CLI and shows it, then discards the
model. The confirmed call builds a fresh model and deploys it only when its CLI matches the preview (the
confirm token binds the CLI). The configuration-model flow also works when the provisioning settings require
preview; with ITSM approval the deploy waits for the ITSM change.

The spec lists the model deploy at a doubled prefix, `/dna/intent/api/v1/intent/api/v1/wired/...`. The tool
uses the single prefix: the doubled form is a 404 ("BAPI not found") for the wired deviceDeployments read and
for the activities API on 3.2.2.

## Open until the live proof (PDC enabled on a lab cat9000v)

- The shape of the read answers (`{"response": ...}` or the spec's bare `{"<feature>": {"items": []}}`): both
  are parsed.
- Whether the first intended feature on a switch needs `POST .../intended/layer2` (the spec says so): the
  tool tries the per-feature POST and falls back to it.
- The name the switch gives the port-channel feature (`portchannelConfig` in the read schema,
  `portChannelConfig` in the request schema): the tool uses whatever `supported/layer2` lists.
