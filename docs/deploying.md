# Deploying catc-mcp-server on a shared host

One container serves a team: each person gets their own token, the server is read-only until you decide
otherwise, TLS ends at a reverse proxy, and one server can reach several Catalyst Centers. Everything below is
in [`examples/shared-host/`](../examples/shared-host/); a laptop (stdio) setup is in the README quickstart.

## 1. What is safe by default

| Setting | Default | What it means |
|---|---|---|
| `MCP_ENABLE_WRITES` | `false` | write tools (sites, settings, credentials, templates, tags, discovery, compliance runs...) are **not registered** |
| `MCP_ENABLE_DANGEROUS` | `false` | template deploys, provisioning, SWIM distribute/activate, PnP claims, RMA, SDA, ISE integration, deletes: not registered; needs writes on too |
| `MCP_AUTH_TOKENS` | none | the HTTP transport **refuses to start** without at least one token (or OAuth) |
| `MCP_DEFAULT_ROLE` | `ro` | once `MCP_ROLES` is set, a caller with no entry gets read tools only (without `MCP_ROLES` every token can use every enabled tier) |
| `CATC_VERIFY_SSL` | `true` | Catalyst Center's certificate is checked; set `CATC_CA_BUNDLE` for a private CA |
| `CATC_MAX_DEVICES_PER_CHANGE` | `10` | no single deploy, provisioning, SWIM, PnP or delete may touch more devices (section 5) |

Turning on writes is two decisions: the server (`MCP_ENABLE_WRITES=true`) and who may use them (`MCP_ROLES`).
Every write tool is preview-first: nothing changes until the caller repeats the call with the confirm token.
The contract tests (`tests/unit/test_tier_defaults.py`) fail if a default or a shipped config turns writes on.

The repository's own `docker-compose.yml` used to set `MCP_ENABLE_WRITES=true`; since 0.9.0 it doesn't, so put
it in `.env` if you relied on it.

## 2. The Catalyst Center account (least privilege, step by step)

Give each server instance its **own** Catalyst Center API user, sized to the tiers that instance enables. A
read-only server and a write server are two containers with two users, never one account with the larger
role. Full permission list and the reasons: [least-privilege.md](least-privilege.md).

1. **Create the role.** *System > Users & Roles > Role Based Access Control > Create a New Role*:
   - read-only server: **`mcp-catc-ro`**, Read on the permissions in least-privilege.md section 1 (Assurance,
     Intent API, Network Design.Profiles & Settings, Inventory, Hierarchy, Compliance, SWIM, Audit Log, System
     Settings, System Administration, Command Runner, ...), everything else Deny;
   - writes on: **`mcp-catc-rw`**, the same plus Write on the section 2 permissions (Profiles & Settings,
     Wireless Maps, Discovery, Hierarchy, Inventory, Compliance, Device Replacement, SWIM);
   - dangerous on: **`mcp-catc-dangerous`**, plus Write on PnP, Device Provision, SD-Access and System
     Settings (template deploys need Device Provision Write). Prefer a separate instance for this tier.

   Never use SUPER-ADMIN-ROLE or NETWORK-ADMIN-ROLE for a shared server.
2. **Bind it to a scope.** *Access groups*: create `mcp-catc-ro_GLOBAL` binding the role to the Global site.
   A user without an access group logs in and reads, but some writes fail inside Catalyst Center (tag
   creation with a NullPointerException).
3. **Create the user.** *User Management > Add*, e.g. `mcp-catc-ro`, role and access group from steps 1-2.
   The password may not contain more than two consecutive characters of the user or full name. In a lab,
   `scripts/seed_access.py` does steps 1-3 through the API.
4. **Keep the password out of `.env`**: `CATC_PASSWORD_FILE=/run/secrets/catc_password` (Docker secret) or
   `CATC_PASSWORD_REF=vault:...` (core `docs/PRODUCTION.md`, "Secrets").
5. **Run the preflight**; it reads the user's roles and compares them with the enabled tiers:

   ```bash
   docker compose exec catc-mcp-server catc-mcp-server check
   ```

   `role` fails when an enabled tier isn't allowed (an OBSERVER or `mcp-catc-ro` user behind
   `MCP_ENABLE_WRITES=true`), warns when the account holds more than the server needs (SUPER-ADMIN-ROLE behind
   a read-only server), and warns when it can't tell (an external/AAA user, or a role it can't read: reading
   users needs System Administration Read). `catc_status` reports the same under `catc.account` at run time.

## 3. Per-user tokens (names in the audit log)

Give each person their own token; the token's name is the caller identity in previews, the audit log and
roles. Never share one token.

```bash
docker run --rm ghcr.io/dr-stutters/catc-mcp-server catc-mcp-server token alice
# prints the token (give it to alice) and the line for the server:  alice:sha256:<hex>
```

Collect the lines in `MCP_AUTH_TOKENS=alice:sha256:...,bob:sha256:...` (or one per line in a file named by
`MCP_AUTH_TOKENS_FILE`). Revoke a person by deleting their entry and restarting. With writes on, say who may
use them:

```bash
MCP_ROLES=alice:rw,bob:ro,oncall-*:admin    # ro = read, rw = + write, admin = + dangerous
```

The example writes the audit log to `/cache/catc-audit.log` (rotated at 50 MB, 5 files): one JSON line per
call, e.g. `{"audit": {"event": "tool_call", "tool": "catc_status", "caller": "alice", "args": {...},
"outcome": "ok"}}`, plus `preview` / `applied` events for writes. Ship it to your log platform, or set
`MCP_AUDIT_LOG=stderr` and use the container log driver.

Catalyst Center's own audit log (`catc_list_audit_logs`) only ever shows the server's API user: the MCP audit
log is where the person is named. Keep both.

## 4. What every caller shares: the token and Catalyst Center's API limits

The server logs in once per Catalyst Center (`POST /dna/system/api/v1/auth/token`) and every caller uses that
X-Auth-Token. It is valid for 60 minutes; the server renews it after 55 minutes (and on a 401), so nobody
sees an expiry. A pre-issued `CATC_TOKEN` is never renewed and stops working after an hour: `check` warns
about it; use a username and password on a shared host.

Catalyst Center rate-limits API clients and answers HTTP 429 when they go too fast. All callers of one server
count against the same API user, so a busy team reaches the limit sooner than one person would:

- the server retries a 429 (honouring `Retry-After`, up to `CATC_RETRIES` times) before it reports the limit;
- `CATC_MAX_CONCURRENCY` (default 8) caps concurrent requests to one Catalyst Center, for all callers together;
- `CATC_RATE_LIMIT` (requests per minute, off by default) paces them client-side; set it if Catalyst Center
  returns many 429s or other integrations share the appliance;
- `MCP_CALLER_RATE_LIMIT` (core, per caller) stops one person's agent from using the whole budget.

Each instance (section 6) has its own login, token and limits.

## 5. Change rails for a team (D19)

These apply on top of preview-first, and only once writes are on:

- **`CATC_MAX_DEVICES_PER_CHANGE`** (default **10**, `0` = off): a template deploy, provisioning, SWIM
  distribute/activate, PnP claim, device replacement or device deletion touching more devices is blocked in
  the preview with "split it into smaller batches". Deploys by `site` count every device under it (child
  sites included; `Global` = the whole inventory) and by `tag` every tagged device, after expansion. Pick a
  number your team would sign off as one change; raising it is an operator decision (restart), not something
  a caller can override.
- **Change window**: `MCP_CHANGE_WINDOW="Sat 22:00-04:00 Australia/Sydney"` refuses every write outside the
  window, for every instance; `CATC_CHANGE_WINDOW` (default instance) or `CATC_<NAME>_CHANGE_WINDOW` applies
  to one Catalyst Center only (production at night, the lab any time). The `catc_change_window` prompt adds a
  per-change deadline (`window_end`) and walks baseline, preview, deploy, verification and a rollback plan.
- **Blast radius**: `MCP_MAX_BLAST_RADIUS` / `MCP_BLAST_RADIUS_OVERRIDES` (e.g. `catc_deploy_template=5`), and
  per instance `CATC_<NAME>_MAX_BLAST_RADIUS`.
- **Two people**: `MCP_TWO_PERSON_TOOLS="@dangerous"` (or `CATC_<NAME>_TWO_PERSON=true`): the confirm must
  come from a different caller than the preview, so one person proposes a deploy and another approves it.
- **Dry run**: `MCP_DRY_RUN=true` previews everything and applies nothing (a training or review host).
- **Read-only instance**: `CATC_<NAME>_READ_ONLY=true` keeps one Catalyst Center read-only on a write server.

`catc_status` lists the rails in force, and a blocked preview says which rail blocked it.

## 6. Several Catalyst Centers from one host

```bash
CATC_URL=https://catc-prod.corp.example      # the default instance
CATC_USERNAME=mcp-catc-ro
CATC_PASSWORD_FILE=/run/secrets/catc_password
CATC_INSTANCES=lab                           # more Catalyst Centers, each with its own variables:
CATC_LAB_URL=https://catc-lab.corp.example
CATC_LAB_USERNAME=mcp-catc-ro
CATC_LAB_PASSWORD_FILE=/run/secrets/catc_lab_password
CATC_LAB_CA_BUNDLE=/certs/lab-ca.pem         # URL, credentials, TLS and write rules are never inherited
CATC_LAB_RATE_LIMIT=120                      # optional: anything else is inherited unless set
```

Every tool then takes an optional `instance` argument (`default` or `lab`); `check` reports each Catalyst
Center. Point each `*_URL` at the cluster's virtual IP or name, not one node. Create the API user on each
Catalyst Center (section 2); the role names can be the same.

## 7. TLS with a reverse proxy (Caddy)

The server speaks plain HTTP inside the compose network; Caddy terminates TLS on 443:

```bash
cd examples/shared-host
cp .env.example .env && chmod 600 .env       # fill in Catalyst Center, tokens, MCP_HOSTNAME
docker compose up -d
curl https://mcp-catc.corp.example/health    # {"status":"ok"}
```

- `MCP_HOSTNAME=mcp-catc.corp.example` and `CADDY_TLS=you@corp.example`: a public name gets a Let's Encrypt
  certificate (ports 80/443 reachable from the internet).
- An internal name: `CADDY_TLS=internal` (Caddy's own CA; copy `/data/caddy/pki/authorities/local/root.crt`
  from the `caddy-data` volume to clients) or mount your own certificate and put
  `tls /certs/mcp.crt /certs/mcp.key` in the `Caddyfile`.
- The MCP server port is not published; only Caddy is. `flush_interval -1` keeps streamed responses flowing.

Clients then use `https://mcp-catc.corp.example/mcp` with `Authorization: Bearer <their token>`.

**Try it first without Catalyst Center:** `docker compose -f docker-compose.yml -f docker-compose.mock.yml up -d`
starts two mocked Catalyst Centers (`default`, `lab`) and a demo token (`mock-alice-token`);
`docker compose -f docker-compose.yml -f docker-compose.mock.yml exec catc-mcp-server catc-mcp-server check`
checks both (they warn about plain HTTP, nothing fails), and `curl -k https://localhost:8444/health` goes
through Caddy.

## 8. Upgrades

- Images: `ghcr.io/dr-stutters/catc-mcp-server:<version>` (and `:latest`); release candidates are
  `:<version>-rcN` and `:rc`, never `:latest`. Pin a version on a shared host (`MCP_IMAGE_TAG=0.9.0`), read the
  [CHANGELOG](../CHANGELOG.md), then `docker compose pull && docker compose up -d`.
- Verify what you run (keyless cosign signature from the release workflow, plus a signed SBOM):

  ```bash
  cosign verify ghcr.io/dr-stutters/catc-mcp-server:0.9.0 \
    --certificate-identity-regexp '^https://github.com/dr-stutters/stutters-mcp-core/.github/workflows/publish-image.yml@' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-repository dr-stutters/catc-mcp-server
  ```

- After an upgrade run `check` again; a release that needs a new Catalyst Center permission says so in the
  CHANGELOG and `role` fails until the account has it.
- Roll back by setting `MCP_IMAGE_TAG` to the previous version. The server keeps no state besides the spec
  cache and the audit log (both in the `/cache` volume), so a rollback needs nothing else.
- Upgrading Catalyst Center: run `check`; `version` compares the release with the bundled API spec (3.2.2
  today) and warns on an untested release (2.3.7 and later should work; older fails).
