"""Template Editor writes: projects and templates (create, update, commit, delete). Deploying a
template to devices is in the dangerous tier (tools/dangerous.py)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    field_changes,
    get_client,
    preview_or_apply,
)

from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list, list_all_templates, resolve_project, resolve_template
from catc_mcp.tools.templates import TemplateRef

FAMILIES = Literal[
    "Switches and Hubs",
    "Routers",
    "Wireless Controller",
    "Unified AP",
    "Security and VPN",
    "Cisco Interfaces and Modules",
]
TP = "/dna/intent/api/v1/template-programmer"


async def project_by_name(app: CatcApp, name: str) -> dict[str, Any] | None:
    try:
        return await resolve_project(app, name)
    except NotFound:
        return None


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create template project")
    async def catc_create_template_project(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=128, description="Project name")],
        description: Annotated[str | None, Field(description="Project description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a template project (a folder for configuration templates). Preview-first; refuses
        a duplicate name. Returns the project id."""
        app: CatcApp = get_client(ctx)
        body: dict[str, Any] = {"name": name, "description": description or name}
        blockers = [f"Project {name!r} already exists."] if await project_by_name(app, name) else []
        plan = Plan(
            f"Create template project {name}",
            details={"method": "POST", "path": f"{TP}/project", "body": body},
            blockers=blockers,
        )

        async def apply() -> Any:
            job = await app.run_job("POST", f"{TP}/project", body, ctx=ctx, what="create project")
            return {"project_id": job.get("data"), "name": name}

        return await preview_or_apply(
            ctx,
            tool="catc_create_template_project",
            args={"name": name, "description": description},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Create template")
    async def catc_create_template(
        ctx: Context,
        project: Annotated[
            str, Field(description="Template project name or id (catc_list_template_projects)")
        ],
        name: Annotated[str, Field(min_length=1, max_length=128, description="Template name")],
        content: Annotated[
            str, Field(description="Template body (CLI with Jinja {{ var }} or Velocity $var variables)")
        ],
        language: Annotated[Literal["JINJA", "VELOCITY"], Field(description="Template language")] = "JINJA",
        software_type: Annotated[
            str, Field(description="Software type the template targets, e.g. 'IOS-XE', 'IOS', 'NX-OS'")
        ] = "IOS-XE",
        device_families: Annotated[
            list[FAMILIES] | None,
            Field(description="Device families it applies to (default Switches and Hubs)"),
        ] = None,
        description: Annotated[str | None, Field(description="Template description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a (not yet committed) configuration template in a project. Variables are detected
        from the content by Catalyst Center. Preview-first; refuses a duplicate name in the project.
        Commit it with catc_commit_template before it can be deployed."""
        app: CatcApp = get_client(ctx)
        args = {
            "project": project,
            "name": name,
            "content": content,
            "language": language,
            "software_type": software_type,
            "device_families": device_families,
            "description": description,
        }
        proj = await resolve_project(app, project)
        families = device_families or ["Switches and Hubs"]
        body: dict[str, Any] = {
            "name": name,
            "projectName": proj["name"],
            "projectId": proj["id"],
            "language": language,
            "softwareType": software_type,
            "deviceTypes": [{"productFamily": f} for f in families],
            "templateContent": content,
            "description": description or "",
        }
        existing = [
            t
            for t in await list_all_templates(app, projectId=proj["id"])
            if str(t.get("name")).lower() == name.lower()
        ]
        plan = Plan(
            f"Create template {proj['name']}/{name}",
            details={"method": "POST", "path": f"{TP}/project/{proj['id']}/template", "body": body},
            blockers=[f"Template {proj['name']}/{name} already exists."] if existing else [],
        )

        async def apply() -> Any:
            job = await app.run_job(
                "POST", f"{TP}/project/{proj['id']}/template", body, ctx=ctx, what="create template"
            )
            return {"template_id": job.get("data"), "name": f"{proj['name']}/{name}", "committed": False}

        return await preview_or_apply(
            ctx, tool="catc_create_template", args=args, confirm=confirm, plan=plan, apply=apply
        )

    @reg.write(title="Update template", destructive=False)
    async def catc_update_template(
        ctx: Context,
        template: TemplateRef,
        content: Annotated[str | None, Field(description="New template body")] = None,
        description: Annotated[str | None, Field(description="New description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a template's content or description (creates uncommitted changes; commit with
        catc_commit_template). Preview-first: shows the old and new values."""
        app: CatcApp = get_client(ctx)
        if content is None and description is None:
            raise InvalidRequest("Give new `content` and/or `description`.")
        ref = await resolve_template(app, template)
        tid = ref.get("templateId") or ref.get("id")
        current = await app.api.get(f"{TP}/template/{tid}")
        if not isinstance(current, dict):
            raise NotFound(f"Template {template!r} could not be read.")
        desired = {
            k: v for k, v in {"templateContent": content, "description": description}.items() if v is not None
        }
        body = {k: v for k, v in current.items() if k not in ("validationErrors",)}
        body.update(desired)
        plan = Plan(
            f"Update template {current.get('projectName')}/{current.get('name')}",
            details={"method": "PUT", "path": f"{TP}/template", "changes": field_changes(current, desired)},
            fingerprint={"content": current.get("templateContent"), "updated": current.get("lastUpdateTime")},
        )

        async def apply() -> Any:
            job = await app.run_job("PUT", f"{TP}/template", body, ctx=ctx, what="update template")
            return {"template_id": tid, "progress": job.get("progress"), "committed": False}

        return await preview_or_apply(
            ctx,
            tool="catc_update_template",
            args={"template": template, "content": content, "description": description},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Commit template", destructive=False)
    async def catc_commit_template(
        ctx: Context,
        template: TemplateRef,
        comment: Annotated[str, Field(min_length=1, description="Version comment")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Commit a template's current content as a new version (required before deploying it).
        Preview-first; shows the next version number."""
        app: CatcApp = get_client(ctx)
        ref = await resolve_template(app, template)
        tid = ref.get("templateId") or ref.get("id")
        versions = ensure_list(ref.get("versionsInfo"))
        current = await app.api.get(f"{TP}/template/{tid}")
        cur = current if isinstance(current, dict) else {}
        body = {"templateId": tid, "comments": comment}
        plan = Plan(
            f"Commit template {ref.get('projectName')}/{ref.get('name')} as version {len(versions) + 1}",
            details={"method": "POST", "path": f"{TP}/template/version", "body": body},
            fingerprint={"content": cur.get("templateContent"), "updated": cur.get("lastUpdateTime")},
        )

        async def apply() -> Any:
            job = await app.run_job("POST", f"{TP}/template/version", body, ctx=ctx, what="commit template")
            return {"template_id": tid, "progress": job.get("progress")}

        return await preview_or_apply(
            ctx,
            tool="catc_commit_template",
            args={"template": template, "comment": comment},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Delete template", destructive=True)
    async def catc_delete_template(
        ctx: Context,
        template: TemplateRef,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a configuration template and all its versions. It doesn't change devices it was
        already deployed to. Preview-first."""
        app: CatcApp = get_client(ctx)
        ref = await resolve_template(app, template)
        tid = ref.get("templateId") or ref.get("id")
        plan = Plan(
            f"Delete template {ref.get('projectName')}/{ref.get('name')}",
            details={
                "method": "DELETE",
                "path": f"{TP}/template/{tid}",
                "versions": len(ensure_list(ref.get("versionsInfo"))),
            },
            fingerprint=tid,
        )

        async def apply() -> Any:
            job = await app.run_job("DELETE", f"{TP}/template/{tid}", ctx=ctx, what="delete template")
            return {"template_id": tid, "progress": job.get("progress")}

        return await preview_or_apply(
            ctx,
            tool="catc_delete_template",
            args={"template": template},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Delete template project", destructive=True)
    async def catc_delete_template_project(
        ctx: Context,
        project: Annotated[str, Field(description="Template project name or id")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a template project together with every template in it. System projects that
        Catalyst Center marks non-deletable are refused. Preview-first: lists the templates that go."""
        app: CatcApp = get_client(ctx)
        proj = await resolve_project(app, project)
        templates = [str(t.get("name")) for t in ensure_list(proj.get("templates")) if isinstance(t, dict)]
        blockers = []
        if proj.get("isDeletable") is False:
            blockers.append(f"Catalyst Center marks project {proj.get('name')!r} as not deletable.")
        plan = Plan(
            f"Delete template project {proj.get('name')} and its {len(templates)} template(s)",
            details={"method": "DELETE", "path": f"{TP}/project/{proj['id']}", "templates": templates},
            fingerprint=sorted(templates),
            blockers=blockers,
        )

        async def apply() -> Any:
            job = await app.run_job("DELETE", f"{TP}/project/{proj['id']}", ctx=ctx, what="delete project")
            return {"project_id": proj["id"], "progress": job.get("progress")}

        return await preview_or_apply(
            ctx,
            tool="catc_delete_template_project",
            args={"project": project},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
