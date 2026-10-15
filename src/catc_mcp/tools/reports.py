"""Reports (roadmap D16) and ITSM integration reads.

Catalyst Center reports are built from a view group (Inventory, Compliance, SWIM, Licensing, ...) and one
of its views, with filters and a format. catc_list_report_views -> catc_get_report_view (formats, filters,
fields) -> catc_create_report (runs now, downloadable) -> catc_list_reports (executions) ->
catc_get_report_content (CSV/JSON text). PDF/TDE content is binary and isn't returned. ITSM:
catc_list_itsm_instances (read only; creating ServiceNow integrations needs a ServiceNow instance and stays
on catc_api_call).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    compact,
    get_client,
    list_result,
    object_result,
    preview_or_apply,
)
from stutters_mcp_core.http import page_of

from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list

DATA = "/dna/intent/api/v1/data"
VIEW_GROUP_VERSIONS = ("2.0.0", "1.0.0", "3.0.0")
GroupRef = Annotated[
    str, Field(description="View group name (e.g. 'Inventory') or id (catc_list_report_views)")
]
ViewRef = Annotated[str, Field(description="View name (e.g. 'All Data') or id")]


async def view_groups(app: CatcApp) -> list[dict[str, Any]]:
    data = await app.api.get(f"{DATA}/view-groups")
    return [
        g
        for g in ensure_list(data.get("response", data) if isinstance(data, dict) else data)
        if isinstance(g, dict)
    ]


async def resolve_group(app: CatcApp, ref: str) -> dict[str, Any]:
    for g in await view_groups(app):
        if ref.strip().lower() in (str(g.get("name")).lower(), str(g.get("viewGroupId")).lower()):
            return g
    raise NotFound(f"No report view group {ref!r}; see catc_list_report_views.")


async def group_views(app: CatcApp, group_id: str) -> list[dict[str, Any]]:
    data = await app.api.get(f"{DATA}/view-groups/{safe_id(group_id, 'view group id')}")
    return [v for v in ensure_list((data or {}).get("views")) if isinstance(v, dict)]


async def resolve_view(app: CatcApp, group: dict[str, Any], ref: str) -> dict[str, Any]:
    gid = str(group["viewGroupId"])
    for v in await group_views(app, gid):
        if ref.strip().lower() in (str(v.get("viewName")).lower(), str(v.get("viewId")).lower()):
            detail = await app.api.get(
                f"{DATA}/view-groups/{gid}/views/{safe_id(str(v['viewId']), 'view id')}"
            )
            return detail if isinstance(detail, dict) else v
    raise NotFound(f"No view {ref!r} in {group.get('name')}; see catc_list_report_views(group=...).")


async def reports(app: CatcApp) -> list[dict[str, Any]]:
    try:
        data = await app.api.get(f"{DATA}/reports")
    except NotFound:  # Catalyst Center answers 404 when no report exists
        return []
    return [
        r
        for r in ensure_list(data.get("response", data) if isinstance(data, dict) else data)
        if isinstance(r, dict)
    ]


async def resolve_report(app: CatcApp, ref: str) -> dict[str, Any]:
    found = [r for r in await reports(app) if ref.strip() in (r.get("name"), r.get("reportId"))]
    if not found:
        raise NotFound(f"No report {ref!r}; see catc_list_reports.")
    if len(found) > 1:
        raise InvalidRequest(f"{len(found)} reports are named {ref!r}; give the report id.")
    return found[0]


def _filter_summary(f: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = compact(
        {"name": f.get("name"), "type": f.get("type"), "required": f.get("required") or None}
    )
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List report views")
    async def catc_list_report_views(
        ctx: Context,
        group: Annotated[str | None, Field(description="A view group: list its views")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> Any:
        """Report view groups (Inventory, Compliance, SWIM, Licensing, EoX, Access Point, ...) or, with
        group, that group's views. Next: catc_get_report_view for formats and filters."""
        app: CatcApp = get_client(ctx)
        if not group:
            rows = [
                compact({k: g.get(k) for k in ("name", "category", "description", "viewGroupId")})
                for g in await view_groups(app)
            ]
            return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)
        g = await resolve_group(app, group)
        views = [
            compact({k: v.get(k) for k in ("viewName", "viewId", "description")})
            for v in await group_views(app, str(g["viewGroupId"]))
        ]
        return list_result(
            page_of(views, limit=limit, offset=offset),
            fmt=response_format,
            extra={"view_group": g.get("name")},
        )

    @reg.read(title="Get report view")
    async def catc_get_report_view(ctx: Context, group: GroupRef, view: ViewRef) -> Any:
        """A report view's formats, filters (name, type) and field groups, i.e. what catc_create_report
        accepts for it."""
        app: CatcApp = get_client(ctx)
        g = await resolve_group(app, group)
        v = await resolve_view(app, g, view)
        return object_result(
            {
                "view_group": g.get("name"),
                "view": v.get("viewName"),
                "view_id": v.get("viewId"),
                "formats": [f.get("format") for f in ensure_list(v.get("formats")) if isinstance(f, dict)],
                "filters": [_filter_summary(f) for f in ensure_list(v.get("filters")) if isinstance(f, dict)],
                "field_groups": [
                    {
                        "name": fg.get("fieldGroupName"),
                        "fields": [x.get("name") for x in ensure_list(fg.get("fields"))],
                    }
                    for fg in ensure_list(v.get("fieldGroups"))
                    if isinstance(fg, dict)
                ],
            }
        )

    @reg.read(title="List reports")
    async def catc_list_reports(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> Any:
        """Reports defined in Catalyst Center with their view, format and executions (newest first: id,
        status, start/end), for catc_get_report_content."""
        app: CatcApp = get_client(ctx)
        rows = []
        for r in await reports(app):
            ex = sorted(
                (e for e in ensure_list(r.get("executions")) if isinstance(e, dict)),
                key=lambda e: e.get("startTime") or 0,
                reverse=True,
            )
            view: dict[str, Any] = r["view"] if isinstance(r.get("view"), dict) else {}
            rows.append(
                compact(
                    {
                        "name": r.get("name"),
                        "report_id": r.get("reportId"),
                        "view_group": r.get("dataCategory"),
                        "view": view.get("name"),
                        "format": (view.get("format") or {}).get("formatType"),
                        "executions": [
                            compact(
                                {
                                    k: e.get(k)
                                    for k in (
                                        "executionId",
                                        "processStatus",
                                        "startTime",
                                        "endTime",
                                        "errors",
                                    )
                                }
                            )
                            for e in ex[:5]
                        ],
                        "execution_count": r.get("executionCount") or len(ex),
                    }
                )
            )
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="Get report content")
    async def catc_get_report_content(
        ctx: Context,
        report: Annotated[str, Field(description="Report name or id")],
        execution_id: Annotated[
            str | None, Field(description="Execution id (default: the newest finished)")
        ] = None,
        max_chars: Annotated[
            int, Field(ge=500, le=200_000, description="Return at most this many characters")
        ] = 20_000,
    ) -> Any:
        """Download a report execution's content (CSV or JSON reports only; PDF/TDE are binary). Long content
        is cut at max_chars with a note."""
        app: CatcApp = get_client(ctx)
        r = await resolve_report(app, report)
        rid = safe_id(str(r["reportId"]), "report id")
        view: dict[str, Any] = r["view"] if isinstance(r.get("view"), dict) else {}
        fmt = str((view.get("format") or {}).get("formatType") or "")
        if fmt not in ("CSV", "JSON"):
            raise InvalidRequest(
                f"The report's format is {fmt or 'unknown'}; only CSV and JSON content can be returned."
            )
        if execution_id is None:
            data: Any = await app.api.get(f"{DATA}/reports/{rid}/executions")
            ex = [
                e
                for e in ensure_list(data.get("executions") if isinstance(data, dict) else data)
                if isinstance(e, dict) and str(e.get("processStatus", "")).upper() in ("SUCCESS", "COMPLETED")
            ]
            if not ex:
                raise NotFound("The report has no finished execution yet; check catc_list_reports and retry.")
            execution_id = str(max(ex, key=lambda e: e.get("startTime") or 0)["executionId"])
        eid = safe_id(execution_id, "execution id")
        text = await app.api.get(f"{DATA}/reports/{rid}/executions/{eid}", expect="text")
        text = str(text or "")
        out: dict[str, Any] = {
            "report": r.get("name"),
            "execution_id": eid,
            "format": fmt,
            "chars": len(text),
        }
        out["content"] = text[:max_chars]
        if len(text) > max_chars:
            out["note"] = f"Cut at {max_chars} of {len(text)} characters; raise max_chars or add filters."
        return object_result(out)

    @reg.write(title="Create report")
    async def catc_create_report(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=100, description="Report name")],
        group: GroupRef,
        view: ViewRef,
        format: Annotated[Literal["CSV", "JSON"], Field(description="Content format")] = "CSV",  # noqa: A002
        filters: Annotated[
            dict[str, list[str]] | None,
            Field(
                description='Filter name -> values, e.g. {"DeviceFamily": ["Routers"]} (catc_get_report_view)'
            ),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a report from a view and run it now (delivery: download). All fields of the view are
        included. Fetch it with catc_get_report_content once its execution finishes (usually under a
        minute). Preview-first."""
        app: CatcApp = get_client(ctx)
        g = await resolve_group(app, group)
        v = await resolve_view(app, g, view)
        blockers: list[str] = []
        formats = {str(f.get("format")): f for f in ensure_list(v.get("formats")) if isinstance(f, dict)}
        if format not in formats:
            blockers.append(f"The view offers {', '.join(formats) or 'no'} formats, not {format}.")
        known = {str(f.get("name")): f for f in ensure_list(v.get("filters")) if isinstance(f, dict)}
        unknown = sorted(set(filters or {}) - set(known))
        if unknown:
            blockers.append(f"Unknown filter(s) {', '.join(unknown)}; the view has {', '.join(known)}.")
        if any(r.get("name") == name for r in await reports(app)):
            blockers.append(f"A report named {name} exists already.")
        body = {
            "name": name,
            "viewGroupId": g["viewGroupId"],
            "dataCategory": g.get("category"),
            "schedule": {"type": "SCHEDULE_NOW"},
            "deliveries": [{"type": "DOWNLOAD", "default": True}],
            "tags": [],
            "view": {
                "viewId": v.get("viewId"),
                "name": v.get("viewName"),
                "format": {"formatType": format, "name": format},
                "fieldGroups": [
                    {
                        "fieldGroupName": fg.get("fieldGroupName"),
                        "fieldGroupDisplayName": fg.get("fieldGroupDisplayName"),
                        "fields": [
                            {"name": x.get("name"), "displayName": x.get("displayName")}
                            for x in ensure_list(fg.get("fields"))
                        ],
                    }
                    for fg in ensure_list(v.get("fieldGroups"))
                    if isinstance(fg, dict)
                ],
                "filters": [
                    {
                        "name": k,
                        "displayName": known[k].get("displayName"),
                        "type": known[k].get("type"),
                        "value": [{"value": x, "displayValue": x} for x in vals],
                    }
                    for k, vals in (filters or {}).items()
                    if k in known
                ],
            },
        }
        plan = Plan(
            f"Create and run report {name} ({g.get('name')} / {v.get('viewName')}, {format})",
            details={
                "method": "POST",
                "path": f"{DATA}/reports",
                "filters": filters or {},
                "fields": sum(len(fg["fields"]) for fg in body["view"]["fieldGroups"]),
            },
            fingerprint={"view": v.get("viewId"), "group": g.get("viewGroupId")},
            blockers=blockers,
        )

        async def apply() -> Any:
            # The view group version isn't exposed by the API; 3.2.2 wants 2.0.0 for Inventory. Try the
            # known ones in order on Catalyst Center's "ViewGroup does not exist ... version" error.
            made: Any = None
            for version in VIEW_GROUP_VERSIONS:
                try:
                    made = await app.api.post(f"{DATA}/reports", {**body, "viewGroupVersion": version})
                    break
                except UpstreamError as e:
                    if "ViewGroup does not exist" not in str(e) or version == VIEW_GROUP_VERSIONS[-1]:
                        raise
            made = made.get("response", made) if isinstance(made, dict) else made
            return {
                "report_id": made.get("reportId") if isinstance(made, dict) else None,
                "next": "catc_get_report_content once the execution finishes (catc_list_reports)",
            }

        return await preview_or_apply(
            ctx,
            tool="catc_create_report",
            args={"name": name, "group": group, "view": view, "format": format, "filters": filters},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Delete report")
    async def catc_delete_report(
        ctx: Context,
        report: Annotated[str, Field(description="Report name or id")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a report and its executions. Preview-first."""
        app: CatcApp = get_client(ctx)
        r = await resolve_report(app, report)
        rid = safe_id(str(r["reportId"]), "report id")
        plan = Plan(
            f"Delete report {r.get('name')}",
            details={"method": "DELETE", "path": f"{DATA}/reports/{rid}"},
            fingerprint=rid,
        )

        async def apply() -> Any:
            return {"deleted": rid, "result": await app.api.delete(f"{DATA}/reports/{rid}")}

        return await preview_or_apply(
            ctx, tool="catc_delete_report", args={"report": report}, confirm=confirm, plan=plan, apply=apply
        )

    @reg.read(title="List ITSM integrations")
    async def catc_list_itsm_instances(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> Any:
        """ITSM (ServiceNow) integration instances configured in Catalyst Center: name, type, URL, status
        (credentials are never shown)."""
        app: CatcApp = get_client(ctx)
        data = await app.api.get("/dna/intent/api/v1/integration-settings/itsm/instances")
        # {"page", "pageSize", "data": [...], "totalRecords"}
        items = ensure_list(data.get("data", data.get("response")) if isinstance(data, dict) else data)
        rows = []
        for i in items:
            if not isinstance(i, dict):
                continue
            conn = (
                (i.get("data") or {}).get("ConnectionSettings", {}) if isinstance(i.get("data"), dict) else {}
            )
            row = compact(
                {k: i.get(k) for k in ("name", "id", "typeId", "description", "dypName", "schemaVersion")}
            )
            if conn.get("Url"):
                row["url"] = conn["Url"]
            rows.append(row)
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            extra={} if rows else {"note": "No ITSM integration configured."},
        )
