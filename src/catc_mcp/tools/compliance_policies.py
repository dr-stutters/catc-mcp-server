"""User compliance policies (D4): policies of rules with regex/string conditions on the running config
or show-command output, assigned to sites; violations per device or per site.

API (3.2.x): /dna/intent/api/v1/compliancePolicys/... Every write returns a task whose `data` is
"id=<uuid>". Site assignment is a full replace of the policy's root sites; the GET returns the
expanded set (the sites and everything below them). Remediation stays on catc_api_call."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import BaseModel, Field, model_validator
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    preview_or_apply,
)
from stutters_mcp_core.http import fetch_all, page_of

from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, is_uuid, pick, resolve_device, resolve_site

CP = "/dna/intent/api/v1/compliancePolicys"
Severity = Literal["CRITICAL", "MAJOR", "MINOR", "WARNING", "INFO"]
PolicyRef = Annotated[str, Field(description="Compliance policy name or id (catc_list_compliance_policies)")]


class ConditionSpec(BaseModel):
    """One check inside a rule."""

    operator: Literal[
        "CONTAINS_STRING", "DOES_NOT_CONTAIN_STRING", "MATCHES_EXPRESSION", "DOES_NOT_MATCH_EXPRESSION"
    ] = Field(description="How `value` is tested against the source text")
    value: str = Field(
        min_length=1, max_length=1000, description="String or regular expression, e.g. '^ip http server'"
    )
    violation_when: Literal["matches", "does_not_match"] = Field(
        description="'matches': the condition being true is the violation (e.g. a forbidden line); "
        "'does_not_match': it being false is the violation (a required line is missing)"
    )
    severity: Severity = Field("MAJOR", description="Violation severity")
    message: str | None = Field(
        None, max_length=100, description="Custom violation message (default: generated)"
    )
    scope: Literal["CONFIGURATION", "DEVICE_COMMAND_OUTPUT"] = Field(
        "CONFIGURATION", description="Test the running configuration, or the output of `show_command`"
    )
    show_command: str | None = Field(
        None, description="Show command whose output is tested (scope DEVICE_COMMAND_OUTPUT)"
    )
    block_start: str | None = Field(
        None,
        description="Regex starting the config blocks to test one by one, e.g. '^interface GigabitEthernet'",
    )

    @model_validator(mode="after")
    def _command_scope(self) -> "ConditionSpec":
        if self.scope == "DEVICE_COMMAND_OUTPUT" and not self.show_command:
            raise ValueError("scope DEVICE_COMMAND_OUTPUT needs show_command")
        return self


class RuleSpec(BaseModel):
    name: str = Field(min_length=1, max_length=255, description="Rule name (unique within the policy)")
    description: str | None = Field(None, max_length=2000, description="What the rule checks")
    device_families: list[
        Literal["Routers", "Switches and Hubs", "Wireless Controller", "Security and VPN"]
    ] = Field(
        ["Routers", "Switches and Hubs"], min_length=1, description="Device families the rule applies to"
    )
    software_type: Literal["IOS", "IOS_XE", "CISCO_CONTROLLER"] = Field("IOS_XE", description="Software type")
    suggested_fix: str | None = Field(None, max_length=2000, description="How to fix a violation")
    impact: str | None = Field(None, max_length=2000, description="Why a violation matters")
    conditions: list[ConditionSpec] = Field(
        min_length=1, max_length=20, description="Checks, evaluated in order"
    )


def condition_body(c: ConditionSpec) -> dict[str, Any]:
    raise_ = "RAISE_VIOLATION_AND_CONTINUE"
    quiet = "DO_NOT_RAISE_VIOLATION_AND_CONTINUE"
    side = "match" if c.violation_when == "matches" else "doesNotMatch"
    action: dict[str, Any] = {
        "matchAction": raise_ if side == "match" else quiet,
        "doesNotMatchAction": raise_ if side == "doesNotMatch" else quiet,
        f"{side}ViolationSeverity": c.severity,
        f"{side}ViolationMessageType": "CUSTOM_MESSAGE" if c.message else "DEFAULT_MESSAGE",
    }
    if c.message:
        action[f"{side}ViolationMessage"] = c.message
    body: dict[str, Any] = {"scope": c.scope, "operator": c.operator, "value": c.value, "action": action}
    if c.scope == "DEVICE_COMMAND_OUTPUT":
        if not c.show_command:
            raise InvalidRequest("scope DEVICE_COMMAND_OUTPUT needs show_command.")
        body["showCommand"] = c.show_command
    if c.block_start:
        body["parseAsBlocks"] = True
        body["blockStartExpression"] = c.block_start
    return body


def rule_body(r: RuleSpec) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": r.name,
        "softwareType": r.software_type,
        "deviceTypes": [{"deviceFamily": f} for f in r.device_families],
    }
    for key, val in (("description", r.description), ("suggestedFix", r.suggested_fix), ("impact", r.impact)):
        if val:
            body[key] = val
    return body


def task_id_of(job: dict[str, Any]) -> str | None:
    """The new object's id from a task's `data` ("id=<uuid>")."""
    data = str(job.get("data") or "").strip()
    value = data.split("=", 1)[1].strip() if data.startswith("id=") else data
    return value if is_uuid(value) else None


async def list_policies(app: CatcApp) -> list[dict[str, Any]]:
    page = await fetch_all(app.pager, app.api, CP, cap=2000)
    return [p for p in page.items if isinstance(p, dict)]


async def resolve_policy(app: CatcApp, ref: str) -> dict[str, Any]:
    ref = ref.strip()
    if is_uuid(ref):
        one = await app.get_response(f"{CP}/{ref}")
        if isinstance(one, dict) and one.get("id"):
            return one
        raise NotFound(f"No compliance policy with id {ref}.")
    found = [p for p in await list_policies(app) if str(p.get("name", "")).lower() == ref.lower()]
    if not found:
        raise NotFound(f"No compliance policy {ref!r}. Use catc_list_compliance_policies.")
    if len(found) > 1:
        raise InvalidRequest(f"Policy name {ref!r} is ambiguous; use its id.")
    return found[0]


def root_ids(ids: list[str], names: dict[str, str]) -> list[str]:
    """The ids not below another id in the set (siteAssignments PUT takes root sites)."""
    paths = {i: names.get(i, i) for i in ids}
    return [
        i
        for i, path in paths.items()
        if not any(j != i and path.startswith(other + "/") for j, other in paths.items())
    ]


async def assigned_site_ids(app: CatcApp, policy_id: str) -> list[str]:
    data = await app.get_response(f"{CP}/{safe_id(policy_id, 'policy id')}/siteAssignments")
    ids = data.get("siteIds") if isinstance(data, dict) else data
    return [str(i) for i in ensure_list(ids)]


async def site_map(app: CatcApp) -> dict[str, str]:
    page = await fetch_all(app.pager, app.api, "/dna/intent/api/v1/sites", cap=20_000)
    return {str(s.get("id")): str(s.get("nameHierarchy")) for s in page.items if isinstance(s, dict)}


def condition_summary(c: dict[str, Any]) -> dict[str, Any]:
    act = c.get("action") or {}
    if str(act.get("matchAction", "")).startswith("RAISE"):
        when, sev = "matches", act.get("matchViolationSeverity")
    elif str(act.get("doesNotMatchAction", "")).startswith("RAISE"):
        when, sev = "does_not_match", act.get("doesNotMatchViolationSeverity")
    else:
        when, sev = "never", None
    out = {
        "seq": c.get("sequenceNumber"),
        "scope": c.get("scope"),
        "operator": c.get("operator"),
        "value": c.get("value"),
        "violation_when": when,
        "severity": sev,
        "show_command": c.get("showCommand"),
        "block_start": c.get("blockStartExpression"),
        "id": c.get("id"),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


def violation_rows(v: dict[str, Any]) -> list[dict[str, Any]]:
    """Flat violation rows. The device view nests them per rule ({ruleName, violations: [...]},
    3.2.2); the site view is already flat."""
    nested = v.get("violations")
    if isinstance(nested, list):
        base = {"rule": v.get("ruleName")}
        out = [{**base, **violation_rows(x)[0]} for x in nested if isinstance(x, dict)]
        out += [{**base, "error": str(e)[:300]} for e in v.get("errors") or []]
        return out
    row = {
        "rule": v.get("ruleName"),
        "device": v.get("hostname"),
        "address": v.get("managementAddress"),
        "severity": v.get("severity"),
        "message": v.get("violationMessage"),
        "condition_seq": v.get("sequenceNumber"),
    }
    return [{k: x for k, x in row.items() if x not in (None, "")}]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List compliance policies")
    async def catc_list_compliance_policies(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """User-defined compliance policies (Provision > Compliance > Policies) with their status
        (ACTIVE, NO_RULES_CONFIGURED, NO_SITES_ASSIGNED...), rule and site counts. Use
        catc_get_compliance_policy for the rules and conditions."""
        app: CatcApp = get_client(ctx)
        rows = [
            pick(p, ["name", "status", "rulesCount", "sitesCount", "source", "description", "id"])
            for p in await list_policies(app)
        ]
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="Get compliance policy")
    async def catc_get_compliance_policy(ctx: Context, policy: PolicyRef) -> dict[str, Any]:
        """One compliance policy: its rules (device families, software type, suggested fix) with
        their conditions (what is tested, whether a match or a non-match is the violation, severity)
        and the sites it is assigned to, by name (including the sites below the assigned ones)."""
        app: CatcApp = get_client(ctx)
        p = await resolve_policy(app, policy)
        pid = safe_id(str(p["id"]), "policy id")
        rules_raw, site_ids, names = await asyncio.gather(
            app.get_response(f"{CP}/{pid}/rules"), assigned_site_ids(app, pid), site_map(app)
        )
        rules = [r for r in ensure_list(rules_raw) if isinstance(r, dict)]
        conds = await asyncio.gather(
            *(
                app.get_response(f"{CP}/{pid}/rules/{safe_id(str(r['id']), 'rule id')}/conditions")
                for r in rules
            )
        )
        out_rules = []
        for r, cs in zip(rules, conds, strict=True):
            row = pick(r, ["name", "description", "softwareType", "suggestedFix", "impact", "id"])
            row["deviceFamilies"] = [
                d.get("deviceFamily") for d in r.get("deviceTypes") or [] if isinstance(d, dict)
            ]
            row["conditions"] = [condition_summary(c) for c in ensure_list(cs) if isinstance(c, dict)]
            out_rules.append(row)
        return {
            **pick(p, ["name", "description", "status", "source", "id"]),
            "rules": out_rules,
            "sites": sorted(names.get(i, i) for i in site_ids),
        }

    @reg.read(title="List compliance violations")
    async def catc_list_compliance_violations(
        ctx: Context,
        device: Annotated[
            str | None, Field(description="Device (hostname, IP, serial or id): its violating policies")
        ] = None,
        policy: Annotated[str | None, Field(description="Only this policy (name or id)")] = None,
        site: Annotated[
            str | None, Field(description="With policy and no device: violations at this site")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Compliance policy violations from the last compliance run (catc_run_compliance), per
        device (every violating policy, or one) or per site for one policy: rule, condition,
        severity and message. Run compliance first after changing a policy or the device config."""
        app: CatcApp = get_client(ctx)
        pol = await resolve_policy(app, policy) if policy else None
        rows: list[dict[str, Any]] = []
        if device:
            dev = await resolve_device(app, device)
            did = safe_id(str(dev["id"]), "device id")
            if pol is not None:
                pols = [pol]
            else:
                pols = [
                    p
                    for p in ensure_list(
                        await app.get_response(
                            f"/dna/intent/api/v1/compliance/networkDevices/{did}/detail/policys"
                        )
                    )
                    if isinstance(p, dict)
                ]
            for p in pols:
                if not (p.get("id") or p.get("policyId")):
                    continue
                pid = safe_id(str(p.get("id") or p.get("policyId")), "policy id")
                path = f"/dna/intent/api/v1/compliance/networkDevices/{did}/detail/policys/{pid}/violations"
                page = await fetch_all(app.pager, app.api, path, cap=1000)
                name = p.get("name") or p.get("policyName")
                for v in page.items:
                    if isinstance(v, dict):
                        rows += [
                            {"policy": name, "device": dev.get("hostname"), **r} for r in violation_rows(v)
                        ]
        elif pol is not None and site:
            st = await resolve_site(app, site)
            sid, pid = safe_id(str(st["id"]), "site id"), safe_id(str(pol["id"]), "policy id")
            path = f"/dna/intent/api/v1/compliance/sites/{sid}/policys/{pid}/violations"
            page = await fetch_all(app.pager, app.api, path, cap=1000)
            rows = [
                {"policy": pol.get("name"), **r}
                for v in page.items
                if isinstance(v, dict)
                for r in violation_rows(v)
            ]
        else:
            raise InvalidRequest("Give a device (optionally with policy), or a policy and a site.")
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.write(title="Create compliance policy")
    async def catc_create_compliance_policy(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=255, description="Policy name (unique)")],
        rules: Annotated[
            list[RuleSpec], Field(min_length=1, max_length=50, description="Rules with their conditions")
        ],
        sites: Annotated[
            list[str] | None, Field(description="Sites to assign it to (hierarchy or id; children included)")
        ] = None,
        description: Annotated[str | None, Field(max_length=2000, description="Policy description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a compliance policy that checks devices against your own standard, e.g. "no ip http
        server" (a MATCHES_EXPRESSION '^ip http server' condition with violation_when='matches') or
        "a login banner is set" ('^banner login' with violation_when='does_not_match'). Creates the
        policy, its rules and conditions, then the site assignment; if a step fails the new policy is
        deleted again. Preview-first. Violations show after catc_run_compliance."""
        app: CatcApp = get_client(ctx)
        args = {
            "name": name,
            "rules": [r.model_dump() for r in rules],
            "sites": sites,
            "description": description,
        }
        bodies = [(rule_body(r), [condition_body(c) for c in r.conditions]) for r in rules]
        st = list({str(x["id"]): x for x in [await resolve_site(app, s) for s in sites or []]}.values())
        blockers = []
        if any(str(p.get("name", "")).lower() == name.lower() for p in await list_policies(app)):
            blockers.append(f"A compliance policy named {name!r} already exists.")
        if len({r.name for r in rules}) != len(rules):
            blockers.append("Rule names must be unique within the policy.")
        plan = Plan(
            f"Create compliance policy {name} ({len(rules)} rules)"
            + (f", assigned to {', '.join(str(s.get('nameHierarchy')) for s in st)}" if st else ""),
            details={
                "policy": {"name": name, "description": description or ""},
                "rules": [{**rb, "conditions": cb} for rb, cb in bodies],
                "sites": [s.get("nameHierarchy") for s in st],
            },
            fingerprint={"sites": [str(x["id"]) for x in st]},
            blockers=blockers,
            side_effects=["Devices at the sites show violations after the next compliance run."]
            if st
            else [],
        )

        async def apply() -> Any:
            job = await app.run_job(
                "POST", CP, {"name": name, "description": description or ""}, ctx=ctx, what="create policy"
            )
            pid = task_id_of(job)
            if not pid:
                found = [
                    p for p in await list_policies(app) if str(p.get("name", "")).lower() == name.lower()
                ]
                pid = str(found[0]["id"]) if found else None
            if not pid:
                raise NotFound(f"Policy {name!r} was created but its id wasn't returned; check the list.")
            pid = safe_id(pid, "policy id")
            try:
                for rb, cbs in bodies:
                    rjob = await app.run_job("POST", f"{CP}/{pid}/rules", rb, ctx=ctx, what="create rule")
                    rid = task_id_of(rjob)
                    if not rid:
                        raise NotFound(f"Rule {rb['name']!r} returned no id.")
                    for cb in cbs:
                        await app.run_job(
                            "POST", f"{CP}/{pid}/rules/{rid}/conditions", cb, ctx=ctx, what="create condition"
                        )
                if st:
                    await app.run_job(
                        "PUT",
                        f"{CP}/{pid}/siteAssignments",
                        {"siteIds": [str(s["id"]) for s in st]},
                        ctx=ctx,
                        what="assign",
                    )
            except Exception as err:
                try:
                    await app.run_job("DELETE", f"{CP}/{pid}", ctx=ctx, what="roll back policy")
                except Exception as rollback:
                    raise UpstreamError(
                        f"{err}. Rolling back also failed ({rollback}): delete policy {name!r} ({pid}) "
                        "with catc_delete_compliance_policy."
                    ) from err
                raise
            final = await resolve_policy(app, pid)
            return pick(final, ["name", "id", "status", "rulesCount", "sitesCount"])

        return await preview_or_apply(
            ctx, tool="catc_create_compliance_policy", args=args, confirm=confirm, plan=plan, apply=apply
        )

    @reg.write(title="Assign compliance policy to sites")
    async def catc_assign_compliance_policy(
        ctx: Context,
        policy: PolicyRef,
        sites: Annotated[
            list[str], Field(min_length=1, max_length=100, description="Site hierarchies or ids")
        ],
        mode: Annotated[
            Literal["add", "remove", "replace"],
            Field(
                description="'add' to the current sites, 'remove' these (and the sites below them), "
                "or 'replace' all"
            ),
        ] = "add",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change which sites a compliance policy applies to (each site includes the sites below it).
        Preview-first; shows the current and the resulting site lists."""
        app: CatcApp = get_client(ctx)
        p = await resolve_policy(app, policy)
        pid = str(p["id"])
        current = await assigned_site_ids(app, pid)
        names = await site_map(app)
        targets = [await resolve_site(app, s) for s in sites]
        tids = list(dict.fromkeys(str(s["id"]) for s in targets))
        roots = root_ids(current, names)

        def under(i: str, root: str) -> bool:
            a, b = names.get(i, i), names.get(root, root)
            return a == b or a.startswith(b + "/")

        blockers: list[str] = []
        if mode == "replace":
            new = root_ids(tids, names)
        elif mode == "add":
            new = root_ids([*roots, *tids], names)
        else:
            new = [r for r in roots if not any(under(r, t) for t in tids)]
            covered = [t for t in tids if any(under(t, r) for r in new)]
            if covered:
                blockers.append(
                    "Can't remove "
                    + ", ".join(names.get(t, t) for t in covered)
                    + ": covered by an assigned parent site. Remove the parent and add back the other "
                    "children, or use mode='replace'."
                )

        def expand(ids: list[str]) -> list[str]:
            return sorted(n for i, n in names.items() if any(under(i, r) for r in ids))

        if set(new) == set(roots):
            blockers.append("No change: the site list would stay the same.")
        plan = Plan(
            f"Set the sites of compliance policy {p.get('name')} ({mode})",
            details={
                "current": sorted(names.get(i, i) for i in current),
                "assigned_roots_after": sorted(names.get(i, i) for i in new),
                "after_including_children": expand(new),
            },
            fingerprint={"policy": pid, "current": sorted(current), "new": sorted(new)},
            blockers=blockers,
        )

        async def apply() -> Any:
            await app.run_job("PUT", f"{CP}/{pid}/siteAssignments", {"siteIds": new}, ctx=ctx, what="assign")
            return {
                "policy": p.get("name"),
                "sites": sorted(names.get(i, i) for i in await assigned_site_ids(app, pid)),
            }

        return await preview_or_apply(
            ctx,
            tool="catc_assign_compliance_policy",
            args={"policy": policy, "sites": sites, "mode": mode},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Delete compliance policy")
    async def catc_delete_compliance_policy(
        ctx: Context, policy: PolicyRef, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Delete a user compliance policy with its rules, conditions and site assignments; its
        violations disappear from the compliance results. System policies can't be deleted.
        Preview-first."""
        app: CatcApp = get_client(ctx)
        p = await resolve_policy(app, policy)
        pid = str(p["id"])
        plan = Plan(
            f"Delete compliance policy {p.get('name')}",
            details=pick(p, ["name", "status", "rulesCount", "sitesCount", "source", "id"]),
            fingerprint={"id": pid, **pick(p, ["rulesCount", "sitesCount"])},
            blockers=["System policies can't be deleted."] if p.get("source") == "SYSTEM" else [],
        )

        async def apply() -> Any:
            await app.run_job("DELETE", f"{CP}/{safe_id(pid, 'policy id')}", ctx=ctx, what="delete policy")
            return {"deleted": p.get("name"), "id": pid}

        return await preview_or_apply(
            ctx,
            tool="catc_delete_compliance_policy",
            args={"policy": policy},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
