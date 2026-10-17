"""Configuration templates (Template Editor): reads and preview, version history and diff, export
(serialize_templates), usage and deployed-version drift."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import difflib
import json
import re
from datetime import UTC, datetime
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    InvalidRequest,
    NotFound,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
)
from catc_mcp._core.formatting import MASK, NOT_SECRET_KEYS, is_secret_key, mask_all, max_chars
from catc_mcp._core.http import OffsetLimit, fetch_all, page_of
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import (
    ensure_list,
    list_all_templates,
    pick,
    resolve_device,
    resolve_project,
    resolve_template,
    window,
)
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
    out: dict[str, Any] = pick(
        p, ["parameterName", "dataType", "required", "defaultValue", "description", "displayName"]
    )
    sel = p.get("selection") or {}
    if isinstance(sel, dict) and sel.get("selectionValues"):
        out["choices"] = list(sel["selectionValues"].values())
    return out


def param_view(p: dict[str, Any]) -> dict[str, Any]:
    """param_summary with a secret variable's default and choices masked (shared with config export)."""
    out = param_summary(p)
    if secret_param(p):
        out.update(
            {k: mask_all(out[k]) for k in ("defaultValue", "choices") if out.get(k) not in (None, "", [])}
        )
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
            out["templateContent"] = redact_template(out["templateContent"])
        if isinstance(out.get("templateParams"), list):
            out["templateParams"] = [param_view(p) for p in out["templateParams"] if isinstance(p, dict)]
        versions = ref.get("versionsInfo") or []
        out["versions"] = [
            {
                **pick(v, ["version", "versionComment", "author", "id"]),
                "committed": ms_text(v.get("versionTime")),
            }
            for v in versions
            if isinstance(v, dict)
        ]
        for key in ("createTime", "lastUpdateTime", "latestVersionTime"):
            if key in out:
                out[key] = ms_text(out[key])
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
    register_depth(reg)


def ms_text(ms: Any) -> Any:
    """Epoch milliseconds -> 'YYYY-MM-DD HH:MM:SS UTC' (other values unchanged)."""
    if isinstance(ms, bool) or not isinstance(ms, int | float):
        return ms
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


DEPLOY_DEVICE_FIELDS = [
    "name",
    "ipAddress",
    "status",
    "detailedStatusMessage",
    "realizedClis",
    "startTime",
    "endTime",
    "deviceId",
]


def _redact(v: Any) -> Any:
    """redact_config for strings, recursively for lists (realizedClis may be a list of lines)."""
    if isinstance(v, str):
        return redact_config(v)
    if isinstance(v, list):
        return [_redact(x) for x in v]
    return v


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
    out = {k: redact_config(v) if isinstance(v, str) else v for k, v in out.items()}
    out["devices"] = [
        {k: _redact(v) for k, v in pick(x, DEPLOY_DEVICE_FIELDS).items()}
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
        succeeded, the CLI actually pushed (realizedClis: what a rollback has to undo) and Catalyst
        Center's detailed message (e.g. the CLI line the device rejected). Use it
        after catc_deploy_template with wait=false, or to re-check an earlier deployment."""
        app: CatcApp = get_client(ctx)
        dep = safe_id(deployment_id, "deployment id")
        d = await app.api.get(f"/dna/intent/api/v1/template-programmer/template/deploy/status/{dep}")
        return object_result(deployment_summary(d))


# --- D36: version history, diff, export, usage and drift --------------------------------------------

TPL = "/dna/intent/api/v1/templates"
TP = "/dna/intent/api/v1/template-programmer"
EXPORT_FORMAT = "catc-mcp-templates"
EXPORT_FORMAT_VERSION = 1
# Template fields carried in an export (besides content, params and versions).
EXPORT_TEMPLATE_FIELDS = ["description", "language", "softwareType", "softwareVariant", "deviceTypes"]
# Template variable fields worth keeping; ids are appliance-specific and dropped.
EXPORT_PARAM_FIELDS = [
    "parameterName",
    "dataType",
    "defaultValue",
    "description",
    "displayName",
    "instructionText",
    "required",
    "notParam",
    "paramArray",
    "group",
    "order",
    "customOrder",
    "selection",
    "range",
    "key",
    "provider",
    "binding",
    "sensitiveField",
]
# Catalyst Center spells it "Deployemnt Id" in some releases.
DEPLOY_ID_RE = re.compile(r"Deploy\w*\s+Id:\s*([0-9a-fA-F-]{36})", re.IGNORECASE)
# Deploy tasks scanned per drift/usage call, so a busy appliance can't make one call unbounded.
DEPLOY_TASK_CAP = 2000
# Deployment status reads in flight at once.
DEPLOY_STATUS_PARALLEL = 8
# GET /task pages from offset 0, although the 3.2.2 spec says 1: the app's 1-based pager would skip
# the newest task (seen live: a fresh deployment stayed invisible until another task followed it).
TASK_PAGER = OffsetLimit(items="response", one_based=False, max_page=500)


def _no_ids(v: Any) -> Any:
    """Drop appliance-specific "id" keys recursively (template variable selections carry them)."""
    if isinstance(v, dict):
        return {k: _no_ids(x) for k, x in v.items() if k != "id" and x not in (None, "", [], {})}
    if isinstance(v, list):
        return [_no_ids(x) for x in v]
    return v


def _version_no(v: Any) -> int:
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return 0


# A masked value that is only a template variable ($pw, ${pw}, {{ pw }}) is no secret: kept as is.
VARIABLE_ONLY_RE = re.compile(r"^(\$!?\{?[\w.]+\}?|\{\{.*\}\})$")
# The one secret-masking rule set for templates and config export (D39 imports these).
# Secret-looking key and variable names on top of the core's SECRET_KEY_RE: SNMPv3 auth/priv phrases
# and keys, hashes, tokens, whatever an endpoint or a template calls them.
TEMPLATE_SECRET_NAME_RE = re.compile(
    r"(phrase|passw|pwd|(^|[_-])pw$|secret|psk|community|token|hash|cipher_?text|(^|[a-z_])key(value)?s?$)",
    re.IGNORECASE,
)
# Names, labels and enums that look like secrets and aren't (on top of the core's NOT_SECRET_KEYS).
NOT_SECRET = {
    "authType",
    "privacyType",
    "snmpMode",
    "authProtocol",
    "privacyProtocol",
    "cliCredentials",
    "snmpv2cReadCredentials",
    "snmpv2cWriteCredentials",
    "snmpv3Credentials",
    "httpReadCredentials",
    "httpWriteCredentials",
    "passphraseType",
    "keyWrap",
}
SECRET_DATA_TYPES = {"SECUREDSTRING", "SECURESTRING", "PASSWORD", "SECRET"}
# Set-assignments in template bodies, one match per statement (several may share a line):
# Velocity `#set($password = "x")` and Jinja `{% set secret = "x" %}`.
TEMPLATE_SET_RES = [
    re.compile(
        r"(?P<keep>#set\s*\(\s*\$!?\{?(?P<name>\w+)\}?\s*=\s*)"
        r"(?P<val>\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[^)\n]*?)(?P<end>\s*\))"
    ),
    re.compile(r"(?P<keep>\{%-?\s*set\s+(?P<name>\w+)\s*=\s*)(?P<val>.*?)(?P<end>\s*-?%\})"),
]


def secret_name(name: str) -> bool:
    """A variable or key name that holds a secret (password, enable_secret, snmp_community, api_token
    ...). The core's NOT_SECRET_KEYS (passwordPolicy ...) and NOT_SECRET win over both patterns."""
    if name in NOT_SECRET_KEYS or name in NOT_SECRET:
        return False
    return is_secret_key(name) or bool(TEMPLATE_SECRET_NAME_RE.search(name))


def _mask_sets(line: str) -> str:
    """Mask the values of set-assignments to secret-named variables (a variable reference stays)."""

    def sub(m: re.Match[str]) -> str:
        val = m["val"].strip().strip("\"'")
        if not secret_name(m["name"]) or not val or VARIABLE_ONLY_RE.match(val):
            return m[0]
        return f'{m["keep"]}"{MASK}"{m["end"]}'

    for pat in TEMPLATE_SET_RES:
        line = pat.sub(sub, line)
    return line


def mask_template_lines(text: str) -> tuple[str, list[int]]:
    """(template body with secret values masked, 1-based numbers of the masked lines). Masks IOS
    secret lines (redact_config) and Velocity/Jinja set-assignments of secret-named variables;
    a value that is just a template variable is no secret and stays; line endings are kept."""
    out, changed = [], []
    for i, raw in enumerate(text.splitlines(keepends=True), 1):
        line = raw.rstrip("\r\n")
        masked = redact_config(line)
        if masked != line and VARIABLE_ONLY_RE.match(line[len(masked.removesuffix(f" {MASK}")) :].strip()):
            masked = line
        masked = _mask_sets(masked)
        if masked != line:
            changed.append(i)
            raw = masked + raw[len(line) :]
        out.append(raw)
    return "".join(out), changed


def redact_template(text: str) -> str:
    """A template body with its secret values masked (shared with config export)."""
    return mask_template_lines(text)[0]


def _masked(text: str, redact: bool) -> tuple[str, list[int]]:
    return mask_template_lines(text) if redact else (text, [])


def secret_param(p: dict[str, Any]) -> bool:
    """A template variable whose values are secrets: flagged sensitive, typed as a secret, or named
    like one."""
    return (
        bool(p.get("sensitiveField"))
        or str(p.get("dataType") or "").upper() in SECRET_DATA_TYPES
        or secret_name(str(p.get("parameterName") or ""))
    )


def _masked_param(p: dict[str, Any], redact: bool) -> tuple[dict[str, Any], bool]:
    """A template variable for the export: secret variables' defaults and choices masked,
    secret-looking text fields redacted. (variable, masked?)."""
    out = _no_ids(pick(p, EXPORT_PARAM_FIELDS))
    if not redact:
        return out, False
    masked = False
    if secret_param(p):
        for key in ("defaultValue", "selection", "range"):
            if out.get(key) not in (None, "", [], {}):
                out[key], masked = MASK, True
    for key in ("defaultValue", "description", "instructionText", "displayName"):
        if isinstance(out.get(key), str) and out[key] != MASK:
            text, lines = _masked(out[key], True)
            if lines:
                out[key], masked = text, True
    return out, masked


def serialize_templates(
    projects: list[dict[str, Any]],
    templates: list[dict[str, Any]],
    *,
    versions: str = "all",
    redact: bool = True,
    source: dict[str, Any] | None = None,
    exported_at: str | None = None,
) -> dict[str, Any]:
    """The template export document (format catc-mcp-templates v1), stable-ordered by project, template
    and version so two exports diff cleanly. Pure: `projects` are {"name", "description"} records and
    `templates` full template records (GET template/{id}) each with a "versions" list from GET
    templates/{id}/versions (plus "versionComment" where known). `versions` is "all", "latest" or
    "none". With `redact`, lines carrying secrets are masked (********) and listed per template in
    "masked_lines"; catc_import_templates refuses those until fixed. Reused by config export (D39)."""
    by_project: dict[str, dict[str, Any]] = {
        str(p.get("name")): {
            "name": p.get("name"),
            "description": p.get("description") or "",
            "templates": [],
        }
        for p in projects
    }
    for t in templates:
        pname = str(t.get("projectName") or "")
        proj = by_project.setdefault(pname, {"name": pname, "description": "", "templates": []})
        content, draft_masked = _masked(str(t.get("templateContent") or ""), redact)
        masked = [f"draft:{n}" for n in draft_masked]
        out: dict[str, Any] = {"name": t.get("name"), **pick(t, EXPORT_TEMPLATE_FIELDS)}
        out["description"] = t.get("description") or ""
        out["deviceTypes"] = sorted(
            (_no_ids(d) for d in ensure_list(t.get("deviceTypes")) if isinstance(d, dict)),
            key=lambda d: json.dumps(d, sort_keys=True),
        )
        tags = [
            str(g.get("name")) for g in ensure_list(t.get("tags")) if isinstance(g, dict) and g.get("name")
        ]
        if tags:
            out["tags"] = sorted(tags)
        if t.get("composite"):
            out["composite"] = True
            out["containingTemplates"] = sorted(
                f"{c.get('projectName')}/{c.get('name')}"
                for c in ensure_list(t.get("containingTemplates"))
                if isinstance(c, dict)
            )
        out["content"] = content
        params = []
        for p in ensure_list(t.get("templateParams")):
            if isinstance(p, dict) and p.get("parameterName"):
                param, param_masked = _masked_param(p, redact)
                params.append(param)
                if param_masked:
                    masked.append(f"param:{p['parameterName']}")
        out["params"] = sorted(
            params, key=lambda p: (_version_no(p.get("order")), str(p.get("parameterName")))
        )
        vers = sorted(
            (v for v in ensure_list(t.get("versions")) if isinstance(v, dict)),
            key=lambda v: _version_no(v.get("version")),
        )
        if versions == "latest":
            vers = vers[-1:]
        elif versions == "none":
            vers = []
        out_versions = []
        for v in vers:
            vcontent, vmasked = _masked(str(v.get("templateContent") or ""), redact)
            masked += [f"v{v.get('version')}:{n}" for n in vmasked]
            out_versions.append(
                {
                    "version": _version_no(v.get("version")),
                    "comment": v.get("versionComment") or "",
                    "author": v.get("author") or "",
                    "committed": ms_text(v.get("versionTime")),
                    "content": vcontent,
                }
            )
        out["versions"] = out_versions
        if masked:
            out["masked_lines"] = masked
        proj["templates"].append(out)
    doc_projects = sorted(by_project.values(), key=lambda p: (str(p["name"]).lower(), str(p["name"])))
    for p in doc_projects:
        p["templates"].sort(key=lambda t: (str(t["name"]).lower(), str(t["name"])))
    doc: dict[str, Any] = {"format": EXPORT_FORMAT, "format_version": EXPORT_FORMAT_VERSION}
    if exported_at:
        doc["exported_at"] = exported_at
    if source:
        doc["source"] = source
    doc["redacted"] = redact
    doc["projects"] = doc_projects
    return doc


def parse_templates_export(doc: Any) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Validate an export document; [(project, template)] in document order. Raises InvalidRequest
    naming what is wrong (wrong format, missing names or content, masked secret lines)."""
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError as e:
            raise InvalidRequest(f"The export is not valid JSON: {e}") from e
    if not isinstance(doc, dict) or doc.get("format") != EXPORT_FORMAT:
        raise InvalidRequest(
            f"Not a template export: expected format {EXPORT_FORMAT!r} (catc_export_templates)."
        )
    if _version_no(doc.get("format_version")) > EXPORT_FORMAT_VERSION:
        raise InvalidRequest(
            f"Export format version {doc.get('format_version')} is newer than this server reads "
            f"({EXPORT_FORMAT_VERSION})."
        )
    out = []
    for p in ensure_list(doc.get("projects")):
        if not isinstance(p, dict) or not p.get("name"):
            raise InvalidRequest("Every project in the export needs a name.")
        for t in ensure_list(p.get("templates")):
            if not isinstance(t, dict) or not t.get("name"):
                raise InvalidRequest(f"A template in project {p['name']!r} has no name.")
            if not isinstance(t.get("content", ""), str):
                raise InvalidRequest(f"Template {p['name']}/{t['name']}: content must be text.")
            out.append((p, t))
    if not out:
        raise InvalidRequest("The export holds no templates.")
    return out


def template_diff(a: str, b: str, a_label: str, b_label: str, context: int = 3) -> dict[str, Any]:
    """Unified diff of two template bodies with added/removed line counts."""
    lines = list(
        difflib.unified_diff(
            a.splitlines(), b.splitlines(), fromfile=a_label, tofile=b_label, n=context, lineterm=""
        )
    )
    added = sum(1 for x in lines if x.startswith("+") and not x.startswith("+++"))
    removed = sum(1 for x in lines if x.startswith("-") and not x.startswith("---"))
    return {"identical": not lines, "added": added, "removed": removed, "diff": "\n".join(lines)}


async def template_versions(
    app: CatcApp, template_id: str, comments: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    """Every committed version of a template with its content, oldest first. `comments` maps version
    ids to commit comments (from the template list's versionsInfo; this API leaves them out)."""
    page = await fetch_all(
        app.pager, app.api, f"{TPL}/{safe_id(template_id, 'template id')}/versions", cap=5000
    )
    out = []
    for v in page.items:
        if not isinstance(v, dict):
            continue
        v = dict(v)
        if comments and str(v.get("versionId")) in comments:
            v["versionComment"] = comments[str(v.get("versionId"))]
        out.append(v)
    out.sort(key=lambda v: _version_no(v.get("version")))
    return out


def version_comments(ref: dict[str, Any]) -> dict[str, str]:
    return {
        str(v.get("id")): str(v.get("versionComment") or "")
        for v in ensure_list(ref.get("versionsInfo"))
        if isinstance(v, dict) and v.get("version")
    }


async def full_template(app: CatcApp, ref: dict[str, Any]) -> dict[str, Any]:
    """The full template record (draft content, params) with its versions attached."""
    tid = str(ref.get("templateId") or ref.get("id"))
    full, versions = await asyncio.gather(
        app.api.get(f"{TP}/template/{safe_id(tid, 'template id')}"),
        template_versions(app, tid, version_comments(ref)),
    )
    rec = dict(full) if isinstance(full, dict) else {}
    rec.setdefault("projectName", ref.get("projectName"))
    rec["id"] = tid
    rec["versions"] = versions
    return rec


async def collect_templates(
    app: CatcApp, project: str | None = None, template: str | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(projects, full templates with versions) for one project or one template - the input of
    serialize_templates."""
    if template:
        refs = [await resolve_template(app, template)]
        proj_names = {str(refs[0].get("projectName"))}
    else:
        proj = await resolve_project(app, str(project))
        refs = await list_all_templates(app, projectId=proj["id"])
        refs = [r for r in refs if str(r.get("projectName")) == str(proj.get("name"))]
        proj_names = {str(proj.get("name"))}
    projects = []
    for name in sorted(proj_names):
        try:
            p = await resolve_project(app, name)
            projects.append({"name": p.get("name"), "description": p.get("description")})
        except NotFound:  # the description is cosmetic
            projects.append({"name": name, "description": ""})
    templates = list(await asyncio.gather(*(full_template(app, r) for r in refs)))
    return projects, templates


def template_ids(refs: list[dict[str, Any]]) -> set[str]:
    """The template ids and committed version ids of these templates (what deploy tasks name)."""
    out = set()
    for t in refs:
        out.add(str(t.get("templateId") or t.get("id")))
        out.update(
            str(v["id"]) for v in ensure_list(t.get("versionsInfo")) if isinstance(v, dict) and v.get("id")
        )
    return out


def latest_version(ref: dict[str, Any]) -> dict[str, Any]:
    versions = [v for v in ensure_list(ref.get("versionsInfo")) if isinstance(v, dict) and v.get("version")]
    return max(versions, key=lambda v: _version_no(v.get("version")), default={})


# "Deployment of  Template: <version id>.ApplicableTargets: ..." (the deploy task's progress).
DEPLOY_TEMPLATE_RE = re.compile(r"Template:\s*([0-9a-fA-F-]{36})")
IN_FLIGHT = {"IN_PROGRESS", "INIT", "PENDING", "SCHEDULED", ""}


async def deployments(
    app: CatcApp, hours: float, template_ids: set[str] | None = None
) -> tuple[list[dict[str, Any]], list[str]]:
    """Template deployments of the last `hours`, oldest first: the deploy tasks Catalyst Center keeps
    (their progress names the deployment id and the template version id), each with its status
    record (version number, per-device result). `template_ids` (template and version ids) skips the
    status reads of other templates' deployments. (deployments, warnings about what was not read)."""
    page = await fetch_all(
        TASK_PAGER,
        app.api,
        "/dna/intent/api/v1/task",
        {"serviceType": "NCTP", "progress": "Template Deploy", **window(hours)},
        cap=DEPLOY_TASK_CAP,
    )
    tasks: dict[str, dict[str, Any]] = {}
    for t in page.items:
        if not isinstance(t, dict):
            continue
        progress = str(t.get("progress") or "")
        m = DEPLOY_ID_RE.search(progress)
        if m and m.group(1) not in tasks:
            tm = DEPLOY_TEMPLATE_RE.search(progress)
            # Filter only on a named template; a task without `Template: <id>` fails open (its status
            # record is read and matched by name later).
            if template_ids is not None and tm and tm.group(1) not in template_ids:
                continue
            tasks[m.group(1)] = {"_started": float(t.get("startTime") or 0), "_template": tm and tm.group(1)}
    unavailable = 0
    limit = asyncio.Semaphore(DEPLOY_STATUS_PARALLEL)

    async def status(dep: str) -> dict[str, Any] | None:
        nonlocal unavailable
        try:
            async with limit:
                s = await app.api.get(f"{TP}/template/deploy/status/{dep}")
        except NotFound:
            return None  # purged
        except UpstreamError:
            unavailable += 1
            return None
        if not isinstance(s, dict):
            return None
        # The status record loses the template fields once the template is deleted; the task kept them.
        return {**s, "templateId": s.get("templateId") or tasks[dep]["_template"], **tasks[dep]}

    found = await asyncio.gather(*(status(d) for d in tasks))
    deps = [d for d in found if d]
    deps.sort(key=lambda d: d["_started"])
    warnings = []
    if not page.complete:
        warnings.append(f"More than {DEPLOY_TASK_CAP} deploy tasks in the window; older ones not scanned.")
    if unavailable:
        warnings.append(
            f"{unavailable} deployment record(s) could not be read; their devices may be missing."
        )
    return deps, warnings


def device_template_states(
    deps: list[dict[str, Any]], templates: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Per (template, device): the version last deployed successfully, the latest committed version
    and the drift state. `templates` are template list records (with versionsInfo). States: current
    (latest version deployed), behind (an older version), deploying (the only attempt in the window
    is still running), failed (no successful deploy in the window; the last attempt failed),
    unknown version (deployed, but the version can't be told)."""
    by_version: dict[str, tuple[dict[str, Any], int | None]] = {}
    by_name: dict[tuple[str, str], dict[str, Any]] = {}
    for t in templates:
        tid = str(t.get("templateId") or t.get("id"))
        t = {**t, "templateId": tid}
        by_version[tid] = (t, None)
        by_name[(str(t.get("projectName")).lower(), str(t.get("name")).lower())] = t
        for v in ensure_list(t.get("versionsInfo")):
            if isinstance(v, dict) and v.get("id") and v.get("version"):
                by_version[str(v["id"])] = (t, _version_no(v["version"]))
    state: dict[tuple[str, str], dict[str, Any]] = {}
    for d in deps:  # oldest first: later deployments overwrite
        tpl, number = by_version.get(str(d.get("templateId")), (None, None))
        if tpl is None:
            tpl = by_name.get((str(d.get("projectName")).lower(), str(d.get("templateName")).lower()))
        if tpl is None:
            continue  # template deleted since, or not one asked about
        # The version: from the version id deployed, else the status record's number.
        version = number or _version_no(d.get("templateVersion")) or None
        for dev in ensure_list(d.get("devices")):
            if not isinstance(dev, dict):
                continue
            key = (str(tpl["templateId"]), str(dev.get("deviceId") or dev.get("identifier")))
            row = state.setdefault(
                key,
                {
                    "template": f"{tpl.get('projectName')}/{tpl.get('name')}",
                    "device": dev.get("name"),
                    "ipAddress": dev.get("ipAddress"),
                    "deviceId": key[1],
                    "templateId": key[0],
                },
            )
            when = ms_text(d.get("_started")) if d.get("_started") else None
            status = str(dev.get("status") or "").upper()
            row["last_attempt"] = {
                "version": version,
                "status": dev.get("status"),
                "at": when,
                "deploymentId": d.get("deploymentId"),
            }
            if status == "SUCCESS":
                row["deployed_at"] = when
                row["deploymentId"] = d.get("deploymentId")
                if version is None:
                    row.pop("deployed_version", None)
                    row["_unknown_version"] = True
                else:
                    row["deployed_version"] = version
                    row.pop("_unknown_version", None)
    out = []
    for (tid, _), row in state.items():
        t = by_version[tid][0]
        latest = _version_no(latest_version(t).get("version"))
        row["latest_version"] = latest
        deployed = row.get("deployed_version")
        last = row["last_attempt"]
        if row.pop("_unknown_version", False):
            row["state"] = "unknown version"
        elif deployed is None:
            row["state"] = "deploying" if str(last.get("status") or "").upper() in IN_FLIGHT else "failed"
        elif deployed >= latest:
            row["state"] = "current"
        else:
            row["state"] = "behind"
            row["versions_behind"] = latest - deployed
        if last.get("deploymentId") == row.get("deploymentId"):
            row.pop("last_attempt")
        out.append(row)
    out.sort(key=lambda r: (r["template"].lower(), str(r.get("device")).lower()))
    return out


DRIFT_NOTE = (
    "Built from template deployments Catalyst Center still has tasks for (catc_deploy_template, the "
    "Template Editor) in the window. Day-N templates pushed by the provisioning flow carry no "
    "deployment record and don't show here; neither do changes made on the device by hand (use "
    "catc_compare_device_configs or compliance for those)."
)


def register_depth(reg: ToolRegistrar) -> None:
    @reg.read(title="List template versions")
    async def catc_list_template_versions(
        ctx: Context,
        template: TemplateRef,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Version history of a template: every committed version with its number, commit time,
        author, comment, size and lines added/removed against the version before, and whether the
        template has uncommitted changes. Compare two versions with catc_diff_template_versions."""
        app: CatcApp = get_client(ctx)
        ref = await resolve_template(app, template)
        full = await full_template(app, ref)
        rows, prev = [], None
        for v in full["versions"]:
            content = str(v.get("templateContent") or "")
            row: dict[str, Any] = {
                "version": _version_no(v.get("version")),
                "committed": ms_text(v.get("versionTime")),
                "author": v.get("author"),
                "comment": v.get("versionComment"),
                "lines": len(content.splitlines()),
            }
            if prev is not None:
                d = template_diff(prev, content, "a", "b", context=0)
                row["changes"] = f"+{d['added']} -{d['removed']}"
            row["versionId"] = v.get("versionId")
            rows.append(row)
            prev = content
        draft = str(full.get("templateContent") or "")
        extra = {
            "template": f"{ref.get('projectName')}/{ref.get('name')}",
            "uncommitted_changes": prev is None or draft != prev,
        }
        rows.reverse()  # newest first
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)

    @reg.read(title="Diff template versions")
    async def catc_diff_template_versions(
        ctx: Context,
        template: TemplateRef,
        from_version: Annotated[
            int | None,
            Field(ge=1, description="Older version number (default: the version before `to_version`)"),
        ] = None,
        to_version: Annotated[
            int | None, Field(ge=1, description="Newer version number (default: the latest committed)")
        ] = None,
        draft: Annotated[
            bool,
            Field(description="Compare against the current uncommitted content instead of `to_version`"),
        ] = False,
        context: Annotated[int, Field(ge=0, le=20, description="Unchanged lines shown around changes")] = 3,
    ) -> ToolResult:
        """Unified diff between two versions of a template (or a version and the uncommitted draft),
        with lines added and removed. Defaults: the latest committed version against the one before
        it. Secret values are masked on both sides."""
        app: CatcApp = get_client(ctx)
        ref = await resolve_template(app, template)
        full = await full_template(app, ref)
        by_no = {_version_no(v.get("version")): v for v in full["versions"]}
        if draft and to_version is not None:
            raise InvalidRequest("Give `to_version` or draft=true, not both.")
        if not by_no and not draft:
            raise InvalidRequest("The template has no committed versions; use draft=true to see it.")
        latest = max(by_no, default=0)
        if draft:
            new_label, new_text = "draft (uncommitted)", str(full.get("templateContent") or "")
            new_no = latest + 1
        else:
            new_no = to_version or latest
            if new_no not in by_no:
                raise InvalidRequest(f"No version {new_no}; versions: {sorted(by_no)}.")
            new_label, new_text = f"version {new_no}", str(by_no[new_no].get("templateContent") or "")
        old_no = (
            from_version if from_version is not None else max((n for n in by_no if n < new_no), default=0)
        )
        if old_no not in by_no:
            if from_version is None:
                raise InvalidRequest(f"There is no version before {new_label}; give from_version.")
            raise InvalidRequest(f"No version {old_no}; versions: {sorted(by_no)}.")
        old_text = str(by_no[old_no].get("templateContent") or "")
        out = {
            "template": f"{ref.get('projectName')}/{ref.get('name')}",
            "from": f"version {old_no}",
            "to": new_label,
            **template_diff(
                _masked(old_text, True)[0],
                _masked(new_text, True)[0],
                f"version {old_no}",
                new_label,
                context,
            ),
        }
        if old_text.splitlines() != new_text.splitlines() and out["identical"]:
            out["note"] = "The versions differ only in masked secret values."
        return object_result(out, shape=False)

    @reg.read(title="Export templates")
    async def catc_export_templates(
        ctx: Context,
        project: Annotated[
            str | None, Field(description="Export every template in this project (name or id)")
        ] = None,
        template: Annotated[
            str | None, Field(description="Or export just this template ('Project/Name', name or id)")
        ] = None,
        versions: Annotated[
            str,
            Field(
                pattern="^(all|latest|none)$",
                description="Committed versions to include: all (default), latest, or none (draft only)",
            ),
        ] = "all",
    ) -> ToolResult:
        """Export a template project, or one template, as a JSON document: content, variables,
        device types and every committed version with its comment, author and time. Feed it to
        catc_import_templates (here or on another Catalyst Center) to recreate the templates with their
        history, or keep it as a reviewable baseline. Lines carrying secrets are masked and listed in
        "masked_lines"; import refuses those templates until the lines are fixed."""
        app: CatcApp = get_client(ctx)
        if bool(project) == bool(template):
            raise InvalidRequest("Give exactly one of `project` or `template`.")
        projects, templates = await collect_templates(app, project, template)
        doc = serialize_templates(
            projects,
            templates,
            versions=versions,
            source={"catalyst_center": await app.version()},
            exported_at=datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        text = json.dumps(doc, indent=1)
        limit = max_chars() * 4
        if len(text) > limit:
            raise InvalidRequest(
                f"The export is {len(text) // 1000} kB, over the {limit // 1000} kB a response may carry "
                f"({len(templates)} template(s)). Export one template at a time, or versions='latest'."
            )
        return ToolResult(content=text, structured_content=doc)

    @reg.read(title="Template usage")
    async def catc_template_usage(
        ctx: Context,
        template: TemplateRef,
        hours: Annotated[
            float, Field(gt=0, le=2160, description="Look-back for deployments in hours (default 30 days)")
        ] = 720,
    ) -> ToolResult:
        """Where a template is used: the network profiles it is attached to, the sites those profiles
        are assigned to, and the devices it was deployed to with the version each one runs against
        the latest committed version (current / behind / failed). Also says whether the template
        has uncommitted changes."""
        from catc_mcp.tools.profiles import profile_site_ids, site_names, template_profile_ids

        app: CatcApp = get_client(ctx)
        ref = await resolve_template(app, template)
        tid = str(ref.get("templateId") or ref.get("id"))
        profiles, (deps, warnings), full = await asyncio.gather(
            template_profile_ids(app, tid),
            deployments(app, hours, template_ids([ref])),
            app.api.get(f"{TP}/template/{tid}"),
        )
        profile_rows = []
        for pid, pname in sorted(profiles.items(), key=lambda kv: kv[1].lower()):
            sites = await site_names(app, await profile_site_ids(app, pid))
            profile_rows.append({"profile": pname, "id": pid, "sites": sites})
        devices = [
            r for r in device_template_states(deps, [{**ref, "templateId": tid}]) if r["templateId"] == tid
        ]
        latest = latest_version(ref)
        latest_text = ""
        if latest.get("id"):
            v = await app.api.get(f"{TP}/template/{safe_id(str(latest['id']))}")
            latest_text = str((v or {}).get("templateContent") or "") if isinstance(v, dict) else ""
        draft = str((full or {}).get("templateContent") or "") if isinstance(full, dict) else ""
        out: dict[str, Any] = {
            "template": f"{ref.get('projectName')}/{ref.get('name')}",
            "templateId": tid,
            "latest_version": _version_no(latest.get("version")) or None,
            "uncommitted_changes": not latest or draft != latest_text,
            "profiles": profile_rows,
            "sites": sorted({s for p in profile_rows for s in p["sites"]}),
            "devices": [{k: v for k, v in r.items() if k not in ("template", "templateId")} for r in devices],
            "drifted_devices": sum(1 for r in devices if r["state"] != "current"),
            "deployments_window_hours": hours,
            "note": DRIFT_NOTE,
        }
        if warnings:
            out["warnings"] = warnings
        return object_result(out, shape=False)

    @reg.read(title="Template drift")
    async def catc_template_drift(
        ctx: Context,
        template: Annotated[
            str | None, Field(description="Only this template ('Project/Name', name or id)")
        ] = None,
        project: Annotated[str | None, Field(description="Only templates in this project")] = None,
        device: Annotated[
            str | None, Field(description="Only this device (hostname, IP, serial or id)")
        ] = None,
        drifted_only: Annotated[
            bool, Field(description="Only devices not on the latest committed version (default false)")
        ] = False,
        hours: Annotated[
            float, Field(gt=0, le=2160, description="Look-back for deployments in hours (default 30 days)")
        ] = 720,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Template drift per device: for every device a template was deployed to, the version it
        last received against the template's latest committed version. state is current, behind
        (an older version is deployed: redeploy, or roll forward on purpose) or failed (the deploy
        never succeeded). Filter by template, project or device."""
        app: CatcApp = get_client(ctx)
        refs = await list_all_templates(app)
        if template:
            one = await resolve_template(app, template)
            refs = [r for r in refs if r.get("templateId") == one.get("templateId")] or [one]
        if project:
            refs = [r for r in refs if str(r.get("projectName", "")).lower() == project.lower()]
        dev_id = str((await resolve_device(app, device))["id"]) if device else None
        deps, warnings = await deployments(app, hours, template_ids(refs) if template or project else None)
        rows = device_template_states(deps, refs)
        if dev_id:
            rows = [r for r in rows if r["deviceId"] == dev_id]
        if drifted_only:
            rows = [r for r in rows if r["state"] != "current"]
        flat = []
        for r in rows:
            last = r.get("last_attempt") or {}
            flat.append(
                {
                    "device": r.get("device"),
                    "template": r["template"],
                    "deployed": r.get("deployed_version"),
                    "latest": r["latest_version"],
                    "state": r["state"],
                    "deployed_at": r.get("deployed_at"),
                    "last_attempt": f"v{last.get('version')} {last.get('status')} {last.get('at')}"
                    if last
                    else None,
                    "ipAddress": r.get("ipAddress"),
                    "deploymentId": r.get("deploymentId"),
                }
            )
        extra: dict[str, Any] = {
            "drifted": sum(1 for r in rows if r["state"] != "current"),
            "deployments_scanned": len(deps),
            "note": DRIFT_NOTE,
        }
        if warnings:
            extra["warnings"] = warnings
        return list_result(page_of(flat, limit=limit, offset=offset), fmt=response_format, extra=extra)
