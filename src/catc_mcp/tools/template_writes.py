"""Template Editor writes: projects and templates (create, update, commit, delete, clone, import).
Deploying a template to devices is in the dangerous tier (tools/dangerous.py)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
import json
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    field_changes,
    get_client,
    preview_or_apply,
)
from catc_mcp._core.formatting import MASK
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list, list_all_templates, resolve_project, resolve_template, seg
from catc_mcp.tools.templates import TemplateRef, parse_templates_export

FAMILIES = Literal[
    "Switches and Hubs",
    "Routers",
    "Wireless Controller",
    "Unified AP",
    "Security and VPN",
    "Cisco Interfaces and Modules",
]
TP = "/dna/intent/api/v1/template-programmer"


def template_task_result(data: Any) -> tuple[Any, list[str]]:
    """(template id, warnings) from a template create/update task's `data`. It is the bare id, or,
    when Catalyst Center has remarks about the content, a JSON string
    {"templateId", "templateErrors": [{"type", "message", "lineNumber"}]}."""
    if isinstance(data, str) and data.startswith("{"):
        with contextlib.suppress(ValueError):
            data = json.loads(data)
    if not isinstance(data, dict):
        return data, []
    warnings = [
        f"line {e.get('lineNumber')}: {e.get('type')}: {e.get('message')}"
        for e in data.get("templateErrors") or []
        if isinstance(e, dict)
    ]
    return data.get("templateId"), warnings


async def project_by_name(app: CatcApp, name: str) -> dict[str, Any] | None:
    try:
        return await resolve_project(app, name)
    except NotFound:
        return None


def register(reg: ToolRegistrar) -> None:
    register_depth(reg)

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
            tid, warnings = template_task_result(job.get("data"))
            out: dict[str, Any] = {"template_id": tid, "name": f"{proj['name']}/{name}", "committed": False}
            if warnings:
                out["template_warnings"] = warnings
            return out

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
        sendable = {k: v for k, v in current.items() if k not in ("validationErrors",)}
        body = {**sendable, **desired}
        # The PUT sends the whole template: diff what is sent against what is there (replace=True).
        changes = field_changes(sendable, body, replace=True)
        plan = Plan(
            f"Update template {current.get('projectName')}/{current.get('name')}",
            details={"method": "PUT", "path": f"{TP}/template", "changes": changes},
            fingerprint={"content": current.get("templateContent"), "updated": current.get("lastUpdateTime")},
        )

        async def apply() -> Any:
            job = await app.run_job("PUT", f"{TP}/template", body, ctx=ctx, what="update template")
            _, warnings = template_task_result(job.get("data"))
            out: dict[str, Any] = {"template_id": tid, "progress": job.get("progress"), "committed": False}
            if warnings:
                out["template_warnings"] = warnings
            return out

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


async def template_names(app: CatcApp, project_id: str) -> set[str]:
    """Lower-cased names of the templates in a project."""
    return {str(t.get("name")).lower() for t in await list_all_templates(app, projectId=project_id)}


def import_steps(t: dict[str, Any], keep_versions: bool) -> tuple[list[dict[str, Any]], str]:
    """(versions to commit in order, the draft content to leave after them) for one exported template."""
    versions = sorted(
        (v for v in ensure_list(t.get("versions")) if isinstance(v, dict)),
        key=lambda v: int(v.get("version") or 0),
    )
    if not keep_versions:
        versions = versions[-1:]
    return versions, str(t.get("content") or "")


def still_masked(t: dict[str, Any], versions: list[dict[str, Any]]) -> list[str]:
    """Where the mask token is in what will be imported ('draft:N', 'vK:N', 'param:name'). Scans the
    content itself, not the export's masked_lines, so a trimmed or edited export can't push the mask
    to devices as a real value."""
    texts = {"draft": str(t.get("content") or "")}
    texts.update({f"v{v.get('version')}": str(v.get("content") or "") for v in versions})
    out = [
        f"{where}:{n}"
        for where, text in texts.items()
        for n, line in enumerate(text.splitlines(), 1)
        if MASK in line
    ]
    out += [
        f"param:{p.get('parameterName')}"
        for p in ensure_list(t.get("params"))
        if isinstance(p, dict) and MASK in json.dumps(p)
    ]
    return out


def import_blockers(t: dict[str, Any], label: str, versions: list[dict[str, Any]]) -> list[str]:
    out = []
    if t.get("composite"):
        out.append(f"{label} is a composite template; import its member templates and rebuild it by hand.")
    masked = still_masked(t, versions)
    if masked:
        out.append(
            f"{label} contains the mask {MASK} where a secret was ({', '.join(masked)}): importing it "
            "would push the mask as the real value. Put the real value (or a template variable) there in "
            "the export and import again."
        )
    return out


def register_depth(reg: ToolRegistrar) -> None:
    @reg.write(title="Clone template", destructive=False)
    async def catc_clone_template(
        ctx: Context,
        template: TemplateRef,
        name: Annotated[str, Field(min_length=1, max_length=128, description="Name of the copy")],
        project: Annotated[
            str | None, Field(description="Project for the copy (name or id; default: the same project)")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Copy a template under a new name, in the same or another project. The copy starts with
        the source's current content and variables and no committed versions (commit it with
        catc_commit_template). To copy with the version history, use catc_export_templates +
        catc_import_templates(name=...). Preview-first; refuses a name already used in the project."""
        app: CatcApp = get_client(ctx)
        ref = await resolve_template(app, template)
        tid = str(ref.get("templateId") or ref.get("id"))
        proj = await resolve_project(app, project or str(ref.get("projectName")))
        path = f"{TP}/clone/name/{seg(name)}/project/{proj['id']}/template/{tid}"
        taken = name.lower() in await template_names(app, proj["id"])
        source = await app.api.get(f"{TP}/template/{tid}")
        src = source if isinstance(source, dict) else {}
        plan = Plan(
            f"Clone template {ref.get('projectName')}/{ref.get('name')} as {proj['name']}/{name}",
            details={
                "method": "POST",
                "path": path,
                "source_versions": len(ensure_list(ref.get("versionsInfo"))),
            },
            blockers=[f"Template {proj['name']}/{name} already exists."] if taken else [],
            fingerprint={
                "source": tid,
                "content": src.get("templateContent"),
                "updated": src.get("lastUpdateTime"),
                "project": proj["id"],
                "taken": taken,
            },
        )

        async def apply() -> Any:
            job = await app.run_job(
                "POST", path, params={"projectId": proj["id"]}, ctx=ctx, what="clone template"
            )
            new_id, warnings = template_task_result(job.get("data"))
            out: dict[str, Any] = {
                "template_id": new_id,
                "name": f"{proj['name']}/{name}",
                "committed": False,
            }
            if warnings:
                out["template_warnings"] = warnings
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_clone_template",
            args={"template": template, "name": name, "project": project},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Import templates")
    async def catc_import_templates(
        ctx: Context,
        export: Annotated[
            dict[str, Any] | str,
            Field(description="The document catc_export_templates returned (object or JSON text)"),
        ],
        project: Annotated[
            str | None,
            Field(
                description="Import into this project (created if missing) instead of the export's projects"
            ),
        ] = None,
        name: Annotated[
            str | None,
            Field(
                min_length=1,
                max_length=128,
                description="New name for the template (import as a copy); only for a single template",
            ),
        ] = None,
        templates: Annotated[
            list[str] | None, Field(description="Only these template names from the export (default all)")
        ] = None,
        keep_versions: Annotated[
            bool,
            Field(description="Recreate every committed version in order (default); false: only the latest"),
        ] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Import templates from a catc_export_templates document: creates missing projects, then
        each template with its committed versions replayed in order (version comments kept; numbers
        start at 1 on this Catalyst Center) and the uncommitted draft on top. Import a copy with
        `name` (one template) and/or `project`. Preview-first: lists every template, its versions and
        the target; refuses names that already exist in the target project, composite templates, and
        lines whose secrets were masked in the export."""
        app: CatcApp = get_client(ctx)
        entries = parse_templates_export(export)
        if templates:
            wanted = {t.lower() for t in templates}
            entries = [(p, t) for p, t in entries if str(t["name"]).lower() in wanted]
            missing = wanted - {str(t["name"]).lower() for _, t in entries}
            if missing:
                raise InvalidRequest(f"Not in the export: {', '.join(sorted(missing))}.")
        if name and len(entries) != 1:
            raise InvalidRequest(
                f"`name` renames one template; the import has {len(entries)} (use `templates`)."
            )
        # Target project per entry, its id (None: created on apply) and the names already there.
        projects: dict[str, dict[str, Any] | None] = {}
        for p, _ in entries:
            pname = project or str(p["name"])
            if pname not in projects:
                projects[pname] = await project_by_name(app, pname)
        existing = {
            pname: (await template_names(app, proj["id"])) if proj else set()
            for pname, proj in projects.items()
        }
        rows, blockers, seen = [], [], set()
        for p, t in entries:
            pname = project or str(p["name"])
            tname = name or str(t["name"])
            label = f"{pname}/{tname}"
            versions, draft = import_steps(t, keep_versions)
            if tname.lower() in existing[pname] or label.lower() in seen:
                blockers.append(f"Template {label} already exists; import a copy with `name` or `project`.")
            seen.add(label.lower())
            blockers += import_blockers(t, label, versions)
            rows.append(
                {
                    "template": label,
                    "from": f"{p['name']}/{t['name']}",
                    "versions_to_commit": [v.get("version") for v in versions],
                    "draft_after": bool(versions) and draft != str(versions[-1].get("content") or ""),
                }
            )
        new_projects = sorted(n for n, proj in projects.items() if proj is None)
        plan = Plan(
            f"Import {len(entries)} template(s) into {', '.join(sorted(projects))}",
            details={"templates": rows, "new_projects": new_projects},
            side_effects=[f"Creates template project {n}." for n in new_projects],
            blockers=blockers,
            fingerprint={n: sorted(names) for n, names in existing.items()},
        )

        async def ensure_project(pname: str, description: str) -> str:
            proj = projects.get(pname) or await project_by_name(app, pname)
            if proj is None:
                job = await app.run_job(
                    "POST",
                    f"{TP}/project",
                    {"name": pname, "description": description or pname},
                    ctx=ctx,
                    what="create project",
                )
                proj = projects[pname] = {"id": job.get("data"), "name": pname}
            return str(proj["id"])

        async def put_content(tid: str, content: str, params: list[Any] | None) -> None:
            current = await app.api.get(f"{TP}/template/{tid}")
            body = {
                k: v
                for k, v in (current if isinstance(current, dict) else {}).items()
                if k != "validationErrors"
            }
            body["templateContent"] = content
            if params is not None:
                body["templateParams"] = params
            await app.run_job("PUT", f"{TP}/template", body, ctx=ctx, what="update template")

        async def import_one(p: dict[str, Any], t: dict[str, Any]) -> dict[str, Any]:
            pname = project or str(p["name"])
            tname = name or str(t["name"])
            pid = await ensure_project(pname, str(p.get("description") or ""))
            versions, draft = import_steps(t, keep_versions)
            contents = [str(v.get("content") or "") for v in versions] or [draft]
            params = [x for x in ensure_list(t.get("params")) if isinstance(x, dict)]

            # Variables (defaults, choices, labels) go with every version, not only the draft.
            send_params = params or None

            body: dict[str, Any] = {
                "name": tname,
                "projectName": pname,
                "projectId": pid,
                "language": t.get("language") or "JINJA",
                "softwareType": t.get("softwareType") or "IOS-XE",
                "deviceTypes": ensure_list(t.get("deviceTypes")) or [{"productFamily": "Switches and Hubs"}],
                "templateContent": contents[0],
                "description": t.get("description") or "",
            }
            if t.get("softwareVariant"):
                body["softwareVariant"] = t["softwareVariant"]
            if send_params:
                body["templateParams"] = params
            job = await app.run_job(
                "POST", f"{TP}/project/{pid}/template", body, ctx=ctx, what="create template"
            )
            new_id, warnings = template_task_result(job.get("data"))
            if not new_id:
                raise UpstreamError(f"Catalyst Center created {pname}/{tname} but returned no template id.")
            tid = partial["template_id"] = str(new_id)
            committed = 0
            for i, v in enumerate(versions):
                if i:
                    await put_content(tid, contents[i], send_params)
                comment = str(v.get("comment") or "") or f"imported version {v.get('version')}"
                await app.run_job(
                    "POST",
                    f"{TP}/template/version",
                    {"templateId": tid, "comments": comment},
                    ctx=ctx,
                    what="commit template",
                )
                committed += 1
            if versions and draft != contents[-1]:
                await put_content(tid, draft, send_params)
            out: dict[str, Any] = {
                "template": f"{pname}/{tname}",
                "template_id": tid,
                "versions_committed": committed,
                "uncommitted_draft": not versions or draft != contents[-1],
            }
            if warnings:
                out["template_warnings"] = warnings
            return out

        partial: dict[str, str | None] = {"template_id": None}

        async def apply() -> Any:
            done: list[dict[str, Any]] = []
            for p, t in entries:
                partial["template_id"] = None
                try:
                    done.append(await import_one(p, t))
                except Exception as e:
                    ok = ", ".join(d["template"] for d in done) or "none"
                    left = (
                        f"; it was created as {partial['template_id']} and is incomplete (delete it with "
                        "catc_delete_template before importing again)"
                        if partial["template_id"]
                        else ""
                    )
                    raise UpstreamError(
                        f"Import stopped at {project or p['name']}/{name or t['name']}{left}: {e}. "
                        f"Imported before it: {ok}."
                    ) from e
            return {"imported": done}

        return await preview_or_apply(
            ctx,
            tool="catc_import_templates",
            args={
                "export": export,
                "project": project,
                "name": name,
                "templates": templates,
                "keep_versions": keep_versions,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
