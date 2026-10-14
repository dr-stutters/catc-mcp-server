"""Configuration templates (Template Editor): reads and preview."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import ResponseFormat, ToolRegistrar, get_client, list_result, object_result
from stutters_mcp_core.http import page_of

from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import list_all_templates, pick, resolve_device, resolve_template
from catc_mcp.tools.inventory import redact_config

TemplateRef = Annotated[
    str, Field(description="Template id, 'Project/Template name', or a unique template name")
]

TEMPLATE_KEEP = [
    "id",
    "name",
    "projectName",
    "projectId",
    "description",
    "language",
    "softwareType",
    "deviceTypes",
    "composite",
    "templateContent",
    "templateParams",
    "containingTemplates",
    "tags",
    "createTime",
    "lastUpdateTime",
    "latestVersionTime",
    "parentTemplateId",
]


def param_summary(p: dict[str, Any]) -> dict[str, Any]:
    out = pick(p, ["parameterName", "dataType", "required", "defaultValue", "description", "displayName"])
    sel = p.get("selection") or {}
    if isinstance(sel, dict) and sel.get("selectionValues"):
        out["choices"] = list(sel["selectionValues"].values())
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List templates")
    async def catc_list_templates(
        ctx: Context,
        project: Annotated[str | None, Field(description="Only templates in this project (name)")] = None,
        name: Annotated[str | None, Field(description="Template name contains (case-insensitive)")] = None,
        software_type: Annotated[str | None, Field(description="Software type, e.g. 'IOS-XE', 'IOS'")] = None,
        committed_only: Annotated[
            bool, Field(description="Hide templates that have never been committed (default false)")
        ] = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Configuration templates (Template Editor) with project, language (Jinja/Velocity), software
        type, device families, committed version count and id. Use catc_get_template for content and
        variables, catc_preview_template to render one."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {}
        if software_type:
            params["softwareType"] = software_type
        templates = await list_all_templates(app, **params)
        rows = []
        for t in templates:
            if project and str(t.get("projectName", "")).lower() != project.lower():
                continue
            if name and name.lower() not in str(t.get("name", "")).lower():
                continue
            versions = t.get("versionsInfo") or []
            if committed_only and not versions:
                continue
            families = sorted(
                {str(d.get("productFamily")) for d in t.get("deviceTypes") or [] if isinstance(d, dict)}
            )
            rows.append(
                {
                    "name": t.get("name"),
                    "projectName": t.get("projectName"),
                    "language": t.get("language"),
                    "softwareType": t.get("softwareType"),
                    "families": ", ".join(families),
                    "versions": len(versions),
                    "composite": t.get("composite"),
                    "templateId": t.get("templateId"),
                }
            )
        rows.sort(key=lambda r: (str(r["projectName"]), str(r["name"])))
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="List template projects")
    async def catc_list_template_projects(
        ctx: Context,
        name: Annotated[str | None, Field(description="Project name contains (case-insensitive)")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Template projects (folders of templates) with description, id and template count."""
        app: CatcApp = get_client(ctx)
        data = await app.api.get("/dna/intent/api/v1/template-programmer/project")
        rows = [
            {
                "name": p.get("name"),
                "description": p.get("description"),
                "templates": len(p.get("templates") or []),
                "deletable": p.get("isDeletable"),
                "id": p.get("id"),
            }
            for p in (data if isinstance(data, list) else [])
            if isinstance(p, dict) and (not name or name.lower() in str(p.get("name", "")).lower())
        ]
        rows.sort(key=lambda r: str(r["name"]))
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="Get template")
    async def catc_get_template(ctx: Context, template: TemplateRef) -> ToolResult:
        """One template in full: content (CLI body), language, variables (name, type, required,
        default, choices), target device families/software, project and version history."""
        app: CatcApp = get_client(ctx)
        ref = await resolve_template(app, template)
        tid = ref.get("templateId") or ref.get("id")
        full = await app.api.get(f"/dna/intent/api/v1/template-programmer/template/{tid}")
        out = pick(full, TEMPLATE_KEEP) if isinstance(full, dict) else {"raw": full}
        if isinstance(out.get("templateContent"), str):
            out["templateContent"] = redact_config(out["templateContent"])
        if isinstance(out.get("templateParams"), list):
            out["templateParams"] = [param_summary(p) for p in out["templateParams"] if isinstance(p, dict)]
        versions = ref.get("versionsInfo") or []
        out["versions"] = [
            pick(v, ["version", "versionTime", "versionComment", "author", "id"])
            for v in versions
            if isinstance(v, dict)
        ]
        return object_result(out)

    @reg.read(title="Preview template", idempotent=True)
    async def catc_preview_template(
        ctx: Context,
        template: TemplateRef,
        params: Annotated[
            dict[str, Any] | None,
            Field(description='Values for the template variables, e.g. {"hostname": "sw1", "vlan": 10}'),
        ] = None,
        device: Annotated[
            str | None,
            Field(description="Optional device (name/IP/id) to render against, for device-bound variables"),
        ] = None,
    ) -> ToolResult:
        """Render a template with the given variable values and show the resulting CLI, without
        deploying anything. Returns the rendered configuration and any validation errors (e.g. missing
        required variables). Check variables first with catc_get_template."""
        app: CatcApp = get_client(ctx)
        ref = await resolve_template(app, template)
        body: dict[str, Any] = {"templateId": ref.get("templateId") or ref.get("id"), "params": params or {}}
        if device:
            body["deviceId"] = (await resolve_device(app, device))["id"]
        result = await app.api.put("/dna/intent/api/v1/template-programmer/template/preview", body)
        if isinstance(result, dict) and isinstance(result.get("cliPreview"), str):
            result["cliPreview"] = redact_config(result["cliPreview"])
        return object_result(result, shape=False)

    register_deployments(reg)


DEPLOY_DEVICE_FIELDS = [
    "name",
    "ipAddress",
    "status",
    "detailedStatusMessage",
    "startTime",
    "endTime",
    "deviceId",
]


def deployment_summary(d: Any) -> dict[str, Any]:
    """The useful part of a template deployment status (per-device result and message)."""
    if not isinstance(d, dict):
        return {"raw": d}
    out = pick(
        d,
        [
            "deploymentId",
            "templateName",
            "projectName",
            "templateVersion",
            "status",
            "statusMessage",
            "startTime",
            "endTime",
            "duration",
        ],
    )
    out["devices"] = [
        {
            k: redact_config(v) if isinstance(v, str) and k == "detailedStatusMessage" else v
            for k, v in pick(x, DEPLOY_DEVICE_FIELDS).items()
        }
        for x in d.get("devices") or []
        if isinstance(x, dict)
    ]
    return out


def register_deployments(reg: ToolRegistrar) -> None:
    @reg.read(title="Get template deployment")
    async def catc_get_template_deployment(
        ctx: Context,
        deployment_id: Annotated[
            str,
            Field(
                description="Deployment id returned by catc_deploy_template (or seen in its task progress)"
            ),
        ],
    ) -> ToolResult:
        """Status of one template deployment: overall status and, per device, whether the push
        succeeded and Catalyst Center's detailed message (e.g. the CLI line the device rejected). Use it
        after catc_deploy_template with wait=false, or to re-check an earlier deployment."""
        app: CatcApp = get_client(ctx)
        dep = safe_id(deployment_id, "deployment id")
        d = await app.api.get(f"/dna/intent/api/v1/template-programmer/template/deploy/status/{dep}")
        return object_result(deployment_summary(d))
