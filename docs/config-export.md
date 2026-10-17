# Config export format (version 1)

`catc_export_config` writes Catalyst Center design intent as YAML; `catc_diff_config` compares two
exports, or an export with live Catalyst Center. Config import (D40) plans from the same document.
The code is `src/catc_mcp/tools/config_io.py`: a fetch layer (`collect`) and a pure layer
(`build_export`, `dump_export`, `load_export`, `diff_exports`) that tests run on recorded fixtures
(`tests/fixtures/config_export_raw.json` → `tests/fixtures/config_export.yaml`, a complete example).

## Rules

- **By name, never by id.** Sites are full paths (`Global/Area/Building/Floor`), credentials
  `TYPE:description`, templates `project/name`, global pools by name. Ids, tenant ids, timestamps and
  counters (pool usage, version counts) are left out, so two exports of an unchanged Catalyst Center
  differ only in `meta.exported_at`.
- **Stable order.** Header (`format`, `version`, `meta`), then the sections in the order below. List
  sections are sorted by identity (sites by path segments, so a parent comes before its children),
  ties broken by the item's canonical JSON; `settings` by site path. In every mapping the keys `path`,
  `site`, `project`, `name`, `ssid`, `type`, `description` come first (in that order), the rest
  alphabetically.
- **Lists inside a record.** Set-like lists are sorted (by the field shown, then canonical JSON):
  `ssidDetails` (ssidName), `apZones` (apZoneName), `rules` (name), `conditions` (sequenceNumber),
  `multiPSKSettings` (priority), and `additionalInterfaces`, `ssids`, `dynamicRules`, `nasOptions`,
  `deviceTypes`, `deviceFamilies`, `tags`, `templates`, `sites`. Template variables are sorted by name
  unless the template sets a custom order. Every other list keeps Catalyst Center's stored order,
  because there the order is the setting: DNS/NTP/DHCP/AAA/syslog/trap server lists (primary first),
  `containingTemplates` (a composite's run order), variable `choices`.
- **Round trip.** `dump(load(text)) == text`, byte for byte. Multi-line strings (template bodies) are
  YAML literal blocks.
- **Secrets are never exported.** Credentials carry type, description and non-secret fields only.
  A final pass over the whole document masks (`********`) the value of every key whose name looks
  secret: the core's list (password, passphrase, secret, community, keys...) plus phrase, pwd, `_pw`,
  psk, token, hash and names ending in key/keyValue (SNMPv3 `authPhrase`, `privKeyValue`...). Flags
  such as `isAuthKeyPSK` and labels such as `cliCredentials` stay readable. In templates: IOS lines
  with passwords/secrets/communities (as `catc_get_template`), Velocity `#set($password = ...)` and
  Jinja `{% set secret = ... %}` assignments to secret-named variables, and the default value and
  choices of a variable with a secret-looking name or a secure data type. An import supplies secrets
  separately.
- **Empty values.** `null` and empty mappings are dropped; empty lists are kept (in a settings body,
  `[]` clears a list).

## Header

```yaml
format: catc-config-export      # always this
version: 1                      # bumped on an incompatible change; readers accept 1..their version
meta:
  catalyst_center: 3.2.2-75131  # release it was read from
  exported_at: '2026-10-17T06:00:00Z'
  scope: Global                 # site subtree the site-bound sections were limited to
  sections: [sites, settings, ...]   # what was asked for
  errors:                       # only when a section could not be read; that section is absent
    ssids: '403 Forbidden ...'
  warnings:                     # items skipped inside a section, and repeated identities
  - 'settings Global/Lab/Bldg/Floor 1 dns: 404 ...'
  - "credentials: 2 items share the name 'CLI:lab' (diff tells them apart as #2, #3...)"
```

Reads run at most 8 at a time across the whole export; Catalyst Center 429s are retried by the API
client (it honours Retry-After and paces itself). One site, template, profile or policy that fails to
read is skipped and named in `warnings`; the rest of its section is exported.

## Sections

| Section | Item identity | Content |
|---|---|---|
| `sites` | `path` | `type` (`area`, `building`, `floor`); buildings: `address`, `latitude`, `longitude`, `country`; floors: `floorNumber`, `rfModel`, `width`, `length`, `height`, `unitsOfMeasure`. The scope's subtree plus its ancestors (not `Global`). |
| `settings` | site path (mapping key) | Per category, the settings **set at that site** (`_inherited=false`), as the body of `PUT /sites/{id}/<category>`: `aaa` (`aaaNetwork`, `aaaClient`), `banner`, `dhcp`, `dns`, `ntp`, `telemetry`, `timezone`, `image_distribution`, and `credentials`, whose slots are renamed without `Id` and name the credential: `cliCredentials: CLI:<description>`. Sites with nothing set are absent. |
| `credentials` | `TYPE:description` | `type`, `description` and the non-secret fields Catalyst Center returns (`username`, `port`, `protocol`, `secure`, `comments`, `snmpMode`, `authType`, `privacyType`). |
| `template_projects` | `name` | `name`, `description`: user projects, and system ones that hold user templates. |
| `templates` | `project/name` | `project`, `name`, `description`, `language`, `softwareType`, `composite`, `failurePolicy`, `deviceTypes` (`productFamily`/`productSeries`/`productType`), `content` (the current body, secrets masked), `params` (variable name, type, required, default, choices), `containingTemplates` (`project/name`), `tags`. System-defined templates are left out. |
| `network_profiles` | `name` | `type` (`Switching`, `Wireless`, ...), `templates` (`project/name`), `sites`: the assigned sites in scope, without the children an assigned parent already covers. |
| `ip_pools` | `name` | Global pools: `type`, `ipv4`/`ipv6` with `subnet`, `prefixLength`, `gatewayIpAddress`, `dhcpServers`, `dnsServers`. |
| `ip_reservations` | `site:name` | Site reservations in scope: `site`, `name`, `type`, `ipv4`/`ipv6` as above plus `globalPool` (name) and `slaacSupport`. |
| `ssids` | `site:ssid` | SSIDs as `GET /sites/{id}/wirelessSettings/ssids` returns them, at the site that defines them (inherited copies are skipped), passphrases masked. |
| `wireless_profiles` | `name` | `ssidDetails` (SSID, interface, fabric, FlexConnect, WLAN/policy profile names), `additionalInterfaces`, `apZones`. |
| `tags` | `name` | User tags: `description`, `dynamicRules` (as the API returns them). |
| `compliance_policies` | `name` | User policies only (`source: SYSTEM` ones are built in): `description`, `rules` (by name: `softwareType`, `deviceFamilies`, `suggestedFix`, `impact`, `conditions` with `scope`, `operator`, `value`, `action`, `sequenceNumber`, ...), `sites` (root assignments in scope). |

`scope` limits the site-bound parts (sites, settings, reservations, SSIDs and the `sites` lists of
profiles and policies). Global objects (credentials, templates, pools, wireless profiles, tags,
policies) are always exported in full; pass `sections` to leave them out.

## Diff

`catc_diff_config(before, after?)` loads both sides (omit `after` for live Catalyst Center, read with
`before`'s scope and sections) and matches items by identity, so order never counts as a change.
`meta` is ignored. Each change is one of:

```yaml
- {section: settings, item: Global/Lab, change: changed, field: dns.dns.domainName, before: a.lab, after: b.lab}
- {section: tags, item: mcp-routers, change: added, after: {...}}
- {section: sites, item: Global/Lab/Old, change: removed, before: {...}}
```

Lists are compared whole (`field` names the list). Items that share an identity (two credentials
`CLI:lab`) are paired identical-first, then in canonical order, and labelled `CLI:lab #2`...; none
is dropped. A section present on only one side is listed in `not_compared`. `summary` counts
added/removed/changed items per section. Values longer than 400 characters (a template body, a whole
added item) are cut and say their length, and the rows stop at `limit` or half the response limit,
whichever comes first (`truncated` says so).

## Size

The export is one tool response, so it is held to `MCP_MAX_RESPONSE_CHARS` (40 000 by default). Over
that, the tool returns an error with the size of each section instead of a truncated document: export
fewer `sections`, a smaller `scope`, or raise the limit.
