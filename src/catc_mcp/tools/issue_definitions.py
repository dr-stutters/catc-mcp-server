"""Assurance issue definitions (roadmap D53): which issues Catalyst Center raises, at what priority and
threshold, plus syslog-pattern custom issues.

System definitions (`/dna/intent/api/v1/systemIssueDefinitions`, 345 on a 3.2.2 appliance) are the
built-in triggers ("BGP Down", "WLC Monitor", ...): each has an enable flag, a priority (P1..P4, with the
factory default alongside) and, for some, a threshold (e.g. how many minutes BGP may be down before the
issue is raised). They exist per Assurance profile; `global` is the default, and a PUT changes the
definition with that id only. Custom definitions (`customIssueDefinitions`) raise an issue when a syslog
message matching a rule (severity, facility, mnemonic, optional regex on the text, N occurrences in M
minutes) arrives from a device.

Both APIs are synchronous (no task) and page with a one-based offset. On the 3.2.2 lab appliance the
custom list answers {"response": [], "page": {"limit": 3, "offset": 1, "count": 0, "sortBy": [...]}}
and `page.count` is the size of the page, not the total, so it isn't used as one.

The system list without `issueEnabled` returns only the ENABLED definitions on 3.2.2 (a disabled one is
missing even with `name=` set; six 2.4 GHz radio definitions ship disabled), so every lookup or listing
that isn't filtered on enabled asks twice, issueEnabled=true and issueEnabled=false, and merges by id.
Custom rules come back with `severity` as a string ("5") although the spec says integer.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
import re
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
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
from catc_mcp._core.http import Page, fetch_all
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, is_uuid

SYSTEM = "/dna/intent/api/v1/systemIssueDefinitions"
CUSTOM = "/dna/intent/api/v1/customIssueDefinitions"
Priority = Literal["P1", "P2", "P3", "P4"]
SEVERITIES = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}
PRIORITY_TEXT = "P1 critical, wide impact; P2 major, several devices or clients; P3 minor, local; P4 warning"


def system_row(d: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "name": d.get("name"),
        "display_name": d.get("displayName"),
        "enabled": d.get("issueEnabled"),
        "priority": d.get("priority"),
        "default_priority": d.get("defaultPriority"),
        "threshold": d.get("thresholdValue"),
        "sync_to_health_threshold": d.get("synchronizeToHealthThreshold"),
        "device_type": d.get("deviceType"),
        "category": d.get("categoryName"),
        "status": d.get("definitionStatus"),
        "profile": d.get("profileId"),
        "description": d.get("description"),
        "id": d.get("id"),
    }
    if d.get("priority") and d.get("defaultPriority") and d["priority"] != d["defaultPriority"]:
        row["changed_from_default"] = True
    return {k: v for k, v in row.items() if v is not None}


def _severity(value: Any) -> int | None:
    """A rule's syslog severity: the appliance returns it as a string ("5"), the spec as an integer."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def rule_text(r: dict[str, Any]) -> str:
    sev = _severity(r.get("severity"))
    parts = [f"severity {sev} ({SEVERITIES.get(sev, '?')})" if sev is not None else "any severity"]
    if r.get("facility") or r.get("mnemonic"):
        parts.append(
            f"%{r.get('facility') or '*'}-{sev if sev is not None else '*'}-{r.get('mnemonic') or '*'}"
        )
    if r.get("pattern"):
        parts.append(f"text matching /{r['pattern']}/")
    occ = r.get("occurrences") or 1
    mins = r.get("durationInMinutes")
    parts.append(f"{occ} time(s)" + (f" in {mins} min" if mins else ""))
    return ", ".join(parts)


def custom_row(d: dict[str, Any]) -> dict[str, Any]:
    rules = [r for r in ensure_list(d.get("rules")) if isinstance(r, dict)]
    row: dict[str, Any] = {
        "name": d.get("name"),
        "enabled": d.get("isEnabled"),
        "priority": d.get("priority"),
        "notify": d.get("isNotificationEnabled"),
        "rules": [rule_text(r) for r in rules],
        "deletable": d.get("isDeletable"),
        "profile": d.get("profileId"),
        "description": d.get("description"),
        "id": d.get("id"),
    }
    return {k: v for k, v in row.items() if v not in (None, "", [])}


def _matches(d: dict[str, Any], search: str) -> bool:
    s = search.lower()
    return any(s in str(d.get(k) or "").lower() for k in ("name", "displayName", "description"))


async def fetch_system(app: CatcApp, params: dict[str, Any], enabled: bool | None = None) -> Page:
    """System definitions matching `params`. With `enabled` None both states are asked for and merged by id
    (the unfiltered GET leaves out disabled definitions on 3.2.2)."""
    states = [enabled] if enabled is not None else [True, False]
    rows: list[Any] = []
    seen: set[str] = set()
    complete = True
    for state in states:
        page = await fetch_all(
            app.pager, app.api, SYSTEM, {**params, "issueEnabled": str(state).lower()}, cap=2000
        )
        complete = complete and page.complete
        for d in page.items:
            if not isinstance(d, dict):
                continue
            key = str(d.get("id") or d.get("name"))
            if key in seen:
                continue
            seen.add(key)
            rows.append(d)
    return Page(items=rows, offset=0, total=len(rows) if complete else None, more=not complete)


async def find_system(app: CatcApp, definition: str, profile: str) -> dict[str, Any]:
    """A system definition by id, name (e.g. BGP_Down) or display name, in one Assurance profile."""
    key = definition.strip()
    if is_uuid(key):
        data = await app.api.get(f"{SYSTEM}/{safe_id(key, 'issue definition id')}")
        d = data.get("response") if isinstance(data, dict) else None
        if isinstance(d, dict) and d.get("id"):
            return d
        raise NotFound(f"No system issue definition {key}.")
    rows = (await fetch_system(app, {"name": key, "profileId": profile})).items
    exact = [d for d in rows if isinstance(d, dict) and d.get("name") == key]
    if exact:
        return exact[0]
    everything = await fetch_system(app, {"profileId": profile})
    by_display = [
        d
        for d in everything.items
        if isinstance(d, dict) and str(d.get("displayName", "")).lower() == key.lower()
    ]
    if len(by_display) == 1:
        return by_display[0]
    near = [str(d.get("name")) for d in everything.items if isinstance(d, dict) and _matches(d, key)][:10]
    if len(by_display) > 1:
        raise InvalidRequest(
            f"{len(by_display)} system issue definitions are displayed as {key!r}: give the name or id "
            f"({', '.join(str(d.get('name')) for d in by_display)})."
        )
    hint = f" Close: {', '.join(near)}." if near else " Find it with catc_list_issue_definitions(search=...)."
    raise NotFound(f"No system issue definition named {key!r} in profile {profile}.{hint}")


async def find_custom(app: CatcApp, definition: str) -> dict[str, Any] | None:
    key = definition.strip()
    if is_uuid(key):
        data: Any = None
        with contextlib.suppress(NotFound):
            data = await app.api.get(f"{CUSTOM}/{safe_id(key, 'custom issue id')}")
        d = data.get("response") if isinstance(data, dict) else None
        if isinstance(d, list):
            d = d[0] if d else None
        return d if isinstance(d, dict) and d.get("id") else None
    data = await app.api.get(CUSTOM, {"name": key})
    rows = [d for d in ensure_list((data or {}).get("response")) if isinstance(d, dict)]
    exact = [d for d in rows if d.get("name") == key]
    return exact[0] if exact else None


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List issue definitions")
    async def catc_list_issue_definitions(
        ctx: Context,
        kind: Annotated[
            Literal["system", "custom"],
            Field(description="system: the built-in triggers; custom: syslog-pattern issues you defined"),
        ] = "system",
        search: Annotated[
            str | None,
            Field(description="Text in the name, display name or description (e.g. 'bgp', 'power')"),
        ] = None,
        name: Annotated[str | None, Field(description="Exact definition name (e.g. BGP_Down)")] = None,
        enabled: Annotated[bool | None, Field(description="Only enabled (true) or disabled (false)")] = None,
        priority: Annotated[Priority | None, Field(description=PRIORITY_TEXT)] = None,
        device_type: Annotated[
            str | None,
            Field(
                description="System only: device family, e.g. ROUTER, SWITCH_AND_HUB, WIRELESS_CONTROLLER, "
                "UNIFIED_AP, SENSOR"
            ),
        ] = None,
        profile: Annotated[
            str, Field(description="Assurance profile id ('global' unless the site uses a custom profile)")
        ] = "global",
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Assurance issue definitions: for each built-in (system) one its name and display name, whether it
        is enabled, its priority next to the factory default, the threshold where it has one (e.g. minutes
        BGP may be down), device type and category; for custom ones the syslog rule in words (severity,
        %FACILITY-SEV-MNEMONIC, text regex, N times in M minutes), priority and whether it notifies. Answers
        "why don't we get BGP issues?" (disabled) and "what alerts on this syslog?". Change one with
        catc_update_issue_definition; add a syslog one with catc_create_custom_issue."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {"profileId": profile}
        if name:
            params["name"] = name
        if priority:
            params["priority"] = priority
        if kind == "system":
            path = SYSTEM
            if device_type:
                params["deviceType"] = device_type
        else:
            if device_type:
                raise InvalidRequest("device_type applies to system definitions only.")
            path = CUSTOM
            if enabled is not None:
                params["isEnabled"] = str(enabled).lower()
        if kind == "system":
            # Both enabled states unless filtered: the unfiltered GET hides disabled definitions.
            everything = await fetch_system(app, params, enabled)
            rows = [
                d for d in everything.items if isinstance(d, dict) and (not search or _matches(d, search))
            ]
            page = Page(
                items=rows[offset : offset + limit],
                offset=offset,
                total=len(rows) if everything.complete else None,
                more=not everything.complete,
            )
        elif search:
            everything = await fetch_all(app.pager, app.api, path, params, cap=2000)
            rows = [d for d in everything.items if isinstance(d, dict) and _matches(d, search)]
            page = Page(items=rows[offset : offset + limit], offset=offset, total=len(rows))
        else:
            page = await app.pager.fetch_page(app.api, path, params, limit=limit, offset=offset)
        shape = system_row if kind == "system" else custom_row
        page.items = [shape(d) for d in page.items if isinstance(d, dict)]
        extra: dict[str, Any] = {"kind": kind, "profile": profile}
        if not page.items and offset == 0:
            extra["note"] = (
                "No custom issue definitions match."
                if kind == "custom"
                else "No system issue definitions match."
            )
        cols = (
            ["name", "enabled", "priority", "default_priority", "threshold", "device_type", "display_name"]
            if kind == "system"
            else ["name", "enabled", "priority", "notify", "rules", "id"]
        )
        return list_result(page, fmt=response_format, columns=cols, extra=extra)

    @reg.write(title="Update issue definition")
    async def catc_update_issue_definition(
        ctx: Context,
        definition: Annotated[
            str,
            Field(description="System definition name (e.g. BGP_Down), display name or id"),
        ],
        enabled: Annotated[
            bool | None, Field(description="false stops Catalyst Center raising this issue; true resumes")
        ] = None,
        priority: Annotated[
            Priority | Literal["default"] | None,
            Field(description=f"New priority ({PRIORITY_TEXT}); 'default' restores the factory one"),
        ] = None,
        threshold: Annotated[
            float | None,
            Field(description="New threshold (only for definitions that have one; same unit as listed)"),
        ] = None,
        sync_to_health_threshold: Annotated[
            bool | None,
            Field(description="Follow the matching health score threshold instead of its own value"),
        ] = None,
        profile: Annotated[str, Field(description="Assurance profile id (when giving a name)")] = "global",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Enable or disable a built-in Assurance issue, or change its priority (P1..P4, or back to the
        default) or threshold: "stop paging me about X". Preview-first: before and after of the definition,
        and what it means (a disabled issue is never raised, for any device in the profile, real problems
        included; notifications and ITSM tickets subscribed to it go quiet). Refused when nothing would
        change or a threshold is given for a definition without one."""
        app: CatcApp = get_client(ctx)
        if enabled is None and priority is None and threshold is None and sync_to_health_threshold is None:
            raise InvalidRequest(
                "Nothing to change: give enabled, priority, threshold or sync_to_health_threshold."
            )
        d = await find_system(app, definition, profile)
        did = str(d.get("id"))
        blockers: list[str] = []
        new_priority = d.get("defaultPriority") if priority == "default" else priority
        has_threshold = d.get("thresholdValue") is not None
        if threshold is not None and not has_threshold:
            blockers.append(f"{d.get('name')} has no threshold to set; only enabled and priority apply.")
        if priority == "default" and not d.get("defaultPriority"):
            blockers.append(f"{d.get('name')} reports no default priority to restore.")
        body: dict[str, Any] = {
            "issueEnabled": d.get("issueEnabled") if enabled is None else enabled,
            "priority": new_priority or d.get("priority"),
            "synchronizeToHealthThreshold": (
                d.get("synchronizeToHealthThreshold")
                if sync_to_health_threshold is None
                else sync_to_health_threshold
            ),
        }
        if has_threshold:
            body["thresholdValue"] = d.get("thresholdValue") if threshold is None else threshold
        body = {k: v for k, v in body.items() if v is not None}
        before = system_row(d)
        after = system_row(
            {
                **d,
                "issueEnabled": body.get("issueEnabled"),
                "priority": body.get("priority"),
                "thresholdValue": body.get("thresholdValue", d.get("thresholdValue")),
                "synchronizeToHealthThreshold": body.get("synchronizeToHealthThreshold"),
            }
        )
        keys = ("enabled", "priority", "threshold", "sync_to_health_threshold")
        changes = {
            k: {"from": before.get(k), "to": after.get(k)} for k in keys if before.get(k) != after.get(k)
        }
        if not changes and not blockers:
            blockers.append(f"{d.get('name')} already has these values; nothing would change.")
        scope = "every device" if d.get("profileId", profile) == "global" else "the sites using this profile"
        side_effects: list[str] = []
        if changes.get("enabled", {}).get("to") is False:
            side_effects.append(
                f"Catalyst Center stops raising '{d.get('displayName') or d.get('name')}' for {scope} "
                f"({d.get('deviceType') or 'all device types'}), real problems included; notifications and "
                "ITSM tickets subscribed to it go quiet. Issues already raised stay until they clear."
            )
        if changes.get("enabled", {}).get("to") is True:
            side_effects.append(
                "New occurrences raise the issue again from now on; past ones aren't back-filled."
            )
        if "priority" in changes:
            side_effects.append(
                "New issues of this type get the new priority (notification subscriptions filtered on "
                "priority follow it)."
            )
        if "threshold" in changes or "sync_to_health_threshold" in changes:
            side_effects.append(
                "The trigger condition changes for new evaluations; existing issues are untouched."
            )
        side_effects.append("No device configuration changes.")
        plan = Plan(
            f"Update issue definition {d.get('name')} ({', '.join(changes) or 'no change'})",
            details={
                "before": before,
                "after": after,
                "changes": changes,
                "method": "PUT",
                "path": f"{SYSTEM}/{did}",
                "body": body,
            },
            side_effects=side_effects,
            fingerprint={"id": did, "current": {k: d.get(k) for k in sorted(d) if k != "lastModified"}},
            blockers=blockers,
        )

        async def apply() -> Any:
            data = await app.api.put(f"{SYSTEM}/{safe_id(did, 'issue definition id')}", json=body)
            got = data.get("response") if isinstance(data, dict) else None
            return {"definition": system_row(got) if isinstance(got, dict) and got else after}

        return await preview_or_apply(
            ctx,
            tool="catc_update_issue_definition",
            args={
                "definition": definition,
                "enabled": enabled,
                "priority": priority,
                "threshold": threshold,
                "sync_to_health_threshold": sync_to_health_threshold,
                "profile": profile,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Create custom issue")
    async def catc_create_custom_issue(
        ctx: Context,
        name: Annotated[
            str,
            Field(min_length=1, max_length=128, description="Issue name (unique; e.g. mcp-ospf-adj-down)"),
        ],
        severity: Annotated[
            int,
            Field(
                ge=0, le=7, description="Syslog severity: 0 emergency .. 3 error, 4 warning, 5 notice, 6 info"
            ),
        ],
        mnemonic: Annotated[str | None, Field(description="Syslog mnemonic, e.g. ADJCHG")] = None,
        facility: Annotated[str | None, Field(description="Syslog facility, e.g. OSPF")] = None,
        pattern: Annotated[
            str | None,
            Field(description="Regular expression the message text must match (e.g. 'from FULL to DOWN')"),
        ] = None,
        occurrences: Annotated[
            int, Field(ge=1, le=60, description="Matching messages needed to raise the issue")
        ] = 1,
        duration_minutes: Annotated[
            int | None,
            Field(ge=1, le=1440, description="Window the occurrences must fall in (with occurrences > 1)"),
        ] = None,
        priority: Annotated[Priority, Field(description=PRIORITY_TEXT)] = "P3",
        description: Annotated[
            str | None,
            Field(max_length=1024, description="What the issue means (default: the rule in words)"),
        ] = None,
        enabled: Annotated[bool, Field(description="Start raising it immediately")] = True,
        notify: Annotated[
            bool, Field(description="Send it to event notification subscriptions (email, webhook, ITSM)")
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a custom (syslog-based) Assurance issue: "alert when this syslog appears". The rule
        matches messages from managed devices by severity plus facility and/or mnemonic (%OSPF-5-ADJCHG ->
        facility OSPF, severity 5, mnemonic ADJCHG) and optionally a regex on the text, N times in M minutes.
        Devices must send syslog to Catalyst Center (site settings) for it to fire. Preview-first: the rule
        in words and the body; refused when the name exists or the rule matches too broadly (no facility,
        mnemonic or pattern)."""
        app: CatcApp = get_client(ctx)
        blockers: list[str] = []
        warnings: list[str] = []
        if not (facility or mnemonic or pattern):
            blockers.append(
                "The rule needs a facility, mnemonic or pattern: severity alone would match every message at "
                "that level from every device."
            )
        if occurrences > 1 and duration_minutes is None:
            blockers.append("Give duration_minutes with occurrences > 1 (N messages within M minutes).")
        if pattern:
            try:
                re.compile(pattern)
            except re.error as err:
                warnings.append(
                    f"The pattern doesn't compile as a Python regex ({err}); Catalyst Center may refuse it."
                )
        existing = await find_custom(app, name)
        if existing:
            blockers.append(f"A custom issue named {name!r} exists already (id {existing.get('id')}).")
        rule: dict[str, Any] = {"severity": severity, "occurrences": occurrences}
        if facility:
            rule["facility"] = facility.strip().upper()
        if mnemonic:
            rule["mnemonic"] = mnemonic.strip().upper()
        if pattern:
            rule["pattern"] = pattern
        if duration_minutes is not None:
            rule["durationInMinutes"] = duration_minutes
        body: dict[str, Any] = {
            "name": name,
            "description": description or f"Raised by syslog: {rule_text(rule)}",
            "priority": priority,
            "isEnabled": enabled,
            "isNotificationEnabled": notify,
            "rules": [rule],
        }
        side_effects = [
            f"Raises a {priority} issue on a device whenever it sends {rule_text(rule)}"
            if enabled
            else "Created disabled: nothing is raised until it's enabled.",
            "No device configuration changes; devices must already send syslog to Catalyst Center.",
        ]
        if notify:
            side_effects.append("Event notification subscriptions for custom issues receive it.")
        side_effects.extend(warnings)
        plan = Plan(
            f"Create custom issue {name} ({priority}, {rule_text(rule)})",
            details={"rule": rule_text(rule), "method": "POST", "path": CUSTOM, "body": body},
            side_effects=side_effects,
            fingerprint={"existing": existing.get("id") if existing else None},
            blockers=blockers,
        )

        async def apply() -> Any:
            data = await app.api.post(CUSTOM, json=body)
            got = data.get("response") if isinstance(data, dict) else None
            if not (isinstance(got, dict) and got.get("id")):
                got = await find_custom(app, name)
            return {"created": custom_row(got) if got else {"name": name}}

        return await preview_or_apply(
            ctx,
            tool="catc_create_custom_issue",
            args={
                "name": name,
                "severity": severity,
                "mnemonic": mnemonic,
                "facility": facility,
                "pattern": pattern,
                "occurrences": occurrences,
                "duration_minutes": duration_minutes,
                "priority": priority,
                "description": description,
                "enabled": enabled,
                "notify": notify,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Delete custom issue", destructive=True)
    async def catc_delete_custom_issue(
        ctx: Context,
        definition: Annotated[str, Field(description="Custom issue name or id")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a custom (syslog-based) issue definition. Preview-first: its rule, priority and whether it
        notifies. Catalyst Center stops raising it on every device. Built-in (system) definitions can't be
        deleted: disable them with catc_update_issue_definition(enabled=false)."""
        app: CatcApp = get_client(ctx)
        d = await find_custom(app, definition)
        if d is None:
            hint = ""
            try:
                sysdef = await find_system(app, definition, "global")
                hint = (
                    f" {sysdef.get('name')} is a system definition: disable it with "
                    "catc_update_issue_definition."
                )
            except (NotFound, InvalidRequest, UpstreamError):
                pass
            raise NotFound(f"No custom issue definition {definition!r}.{hint}")
        did = str(d.get("id"))
        row = custom_row(d)
        blockers = []
        if d.get("isDeletable") is False:
            blockers.append(f"Catalyst Center marks {d.get('name')} as not deletable; disable it instead.")
        side_effects = [
            "Catalyst Center stops raising this issue on every device; issues it already raised stay until "
            "they clear.",
            "No device configuration changes.",
        ]
        if d.get("isNotificationEnabled"):
            side_effects.insert(1, "Notifications subscribed to it stop.")
        plan = Plan(
            f"Delete custom issue {d.get('name')} ({d.get('priority')})",
            details={"definition": row, "method": "DELETE", "path": f"{CUSTOM}/{did}"},
            side_effects=side_effects,
            fingerprint={"id": did, "rules": d.get("rules"), "enabled": d.get("isEnabled")},
            blockers=blockers,
        )

        async def apply() -> Any:
            await app.api.delete(f"{CUSTOM}/{safe_id(did, 'custom issue id')}")
            return {"deleted": did, "name": d.get("name")}

        return await preview_or_apply(
            ctx,
            tool="catc_delete_custom_issue",
            args={"definition": definition},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
