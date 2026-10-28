"""Visibility and Control of Configurations (roadmap D128): Catalyst Center's global provisioning settings
(System > Settings > Visibility and Control of Configurations).

`GET /dna/intent/api/v1/provisioningSettings` answers `{"response": {"requirePreview": bool,
"requireItsmApproval": bool}, "version": "1.0"}` (3.2.2 lab: requirePreview true, requireItsmApproval false).
`PUT` takes both fields (both required by the 3.2.2 spec) and answers 202 with a task id. With
requirePreview on, every provisioning flow must produce a configuration preview that is reviewed before it
deploys; requireItsmApproval additionally sends that preview to the ITSM (ServiceNow) integration for
approval, and turns requirePreview on with it. The setting is global: one change alters how every
provision, template deploy, wireless deploy and SWIM operation of this server behaves, so the write is
dangerous tier. Catalyst Center refuses such a write with 422 'config preview mandated' (or similar), and
the client points that error back to this setting (client.CatcApiClient).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    preview_or_apply,
)
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list

PATH = "/dna/intent/api/v1/provisioningSettings"
ITSM_PATH = "/dna/intent/api/v1/integration-settings/itsm/instances"
# Curated tools whose behaviour follows these settings (the flows Catalyst Center gates).
GATED_TOOLS = {
    "catc_provision_devices": "wired device provisioning",
    "catc_provision_site": "provisioning a site's devices",
    "catc_provision_wireless_controller": "wireless controller provisioning",
    "catc_deploy_template": "template deployment",
    "catc_deploy_wlc_config": "per-device 9800 intended deploy (refused outright while either is on)",
    "catc_distribute_image": "SWIM image distribution",
    "catc_activate_image": "SWIM image activation",
}


def settings_of(body: Any) -> dict[str, bool | None]:
    """{"require_preview", "require_itsm_approval"} from the response (bare or inside "response")."""
    inner = body.get("response", body) if isinstance(body, dict) else {}
    inner = inner if isinstance(inner, dict) else {}

    def flag(key: str) -> bool | None:
        v = inner.get(key)
        return v if isinstance(v, bool) else None

    return {"require_preview": flag("requirePreview"), "require_itsm_approval": flag("requireItsmApproval")}


async def read_settings(app: CatcApp) -> dict[str, bool | None]:
    return settings_of(await app.api.get(PATH))


async def itsm_instances(app: CatcApp) -> list[dict[str, Any]]:
    data = await app.api.get(ITSM_PATH)
    items = ensure_list(data.get("data", data.get("response")) if isinstance(data, dict) else data)
    return [{k: i.get(k) for k in ("name", "id") if i.get(k)} for i in items if isinstance(i, dict)]


def explain(s: dict[str, bool | None]) -> str:
    if s["require_itsm_approval"]:
        return (
            "Every provision and deploy produces a configuration preview that must be approved in the ITSM "
            "(ServiceNow) integration before Catalyst Center runs it."
        )
    if s["require_preview"]:
        return (
            "Every provision and deploy produces a configuration preview that must be reviewed (Work Items) "
            "before it runs; some API flows are refused outright (422 'config preview mandated', and the "
            "per-device 9800 intended deploy)."
        )
    if s["require_preview"] is False:
        return "Provisions and deploys run straight away; no configuration preview or approval is required."
    return "Catalyst Center did not report the setting."


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Provisioning settings (Visibility and Control of Configurations)")
    async def catc_get_provisioning_settings(ctx: Context) -> dict[str, Any]:
        """Catalyst Center's global provisioning settings (System > Settings > Visibility and Control of
        Configurations): require_preview (every provision/deploy must produce a configuration preview that
        is reviewed before it runs) and require_itsm_approval (that preview also needs ITSM/ServiceNow
        approval; implies require_preview), what that means for this server's provision, template deploy,
        wireless deploy and SWIM tools, and the ITSM integrations configured. Change it with
        catc_set_provisioning_settings."""
        app: CatcApp = get_client(ctx)
        s = await read_settings(app)
        out: dict[str, Any] = {**s, "meaning": explain(s)}
        if s["require_preview"] or s["require_itsm_approval"]:
            out["affected_tools"] = GATED_TOOLS
        try:
            out["itsm_instances"] = await itsm_instances(app)
        except UpstreamError as e:
            out["itsm_instances"] = f"unavailable: {str(e)[:150]}"
        return out

    @reg.dangerous(title="Change provisioning settings (Visibility and Control of Configurations)")
    async def catc_set_provisioning_settings(
        ctx: Context,
        require_preview: Annotated[
            bool | None,
            Field(description="Every provision/deploy needs a reviewed configuration preview (omit: keep)"),
        ] = None,
        require_itsm_approval: Annotated[
            bool | None,
            Field(
                description="The preview also needs ITSM (ServiceNow) approval; needs an ITSM integration "
                "and turns require_preview on (omit: keep)"
            ),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Turn Catalyst Center's 'Visibility and Control of Configurations' on or off (System > Settings):
        require_preview and/or require_itsm_approval, with PUT provisioningSettings. GLOBAL: it changes how
        every provision, template deploy, wireless deploy and SWIM run behaves for every user of this
        Catalyst Center, not just this server; the preview names the tools affected. require_itsm_approval
        =true is refused when no ITSM integration is configured (catc_list_itsm_instances), since every
        deploy would then wait for an approval that can never come. Change-controlled sites keep these on:
        turn them off only for an approved window and back on afterwards. Dangerous tier; preview-first."""
        app: CatcApp = get_client(ctx)
        if require_preview is None and require_itsm_approval is None:
            raise InvalidRequest("Give require_preview and/or require_itsm_approval.")
        current = await read_settings(app)
        if current["require_preview"] is None or current["require_itsm_approval"] is None:
            raise UpstreamError(
                f"Can't read the provisioning settings ({PATH}): got no requirePreview/ITSM flags."
            )
        want_itsm = (
            current["require_itsm_approval"] if require_itsm_approval is None else require_itsm_approval
        )
        # ITSM approval implies preview (spec: "requirePreview will default to enabled").
        want_preview = (
            (True if want_itsm else current["require_preview"])
            if require_preview is None
            else require_preview
        )
        blockers: list[str] = []
        if want_itsm and not want_preview:
            blockers.append(
                "require_itsm_approval=true needs require_preview=true: ITSM approval works on the "
                "configuration preview."
            )
        itsm: list[dict[str, Any]] | None = None
        if want_itsm and not current["require_itsm_approval"]:
            try:
                itsm = await itsm_instances(app)
            except UpstreamError as e:
                blockers.append(f"Can't read the ITSM integrations ({ITSM_PATH}): {str(e)[:200]}")
            else:
                if not itsm:
                    blockers.append(
                        "No ITSM integration is configured (catc_list_itsm_instances is empty): with "
                        "require_itsm_approval on, every provision and deploy would wait for an approval "
                        "that can never come. Integrate ServiceNow first."
                    )
        target = {"require_preview": want_preview, "require_itsm_approval": want_itsm}
        body = {"requirePreview": want_preview, "requireItsmApproval": want_itsm}
        effects: list[str] = []
        if want_preview and not current["require_preview"]:
            effects.append(
                "Every provision and deploy then needs a reviewed configuration preview before it runs "
                "(Work Items in the GUI); API calls that skip it are refused (422 'config preview "
                "mandated'), and catc_deploy_wlc_config is refused outright."
            )
        if not want_preview and current["require_preview"]:
            effects.append(
                "Provisions and deploys then run straight away with no Catalyst Center configuration "
                "preview or review step: only this server's own previews remain. Turn it back on after "
                "the change window."
            )
        if want_itsm and not current["require_itsm_approval"]:
            effects.append(
                "Every provision and deploy then waits for approval in the ITSM integration "
                + (f"({', '.join(str(i.get('name') or i.get('id')) for i in itsm)})" if itsm else "")
                + " before it runs."
            )
        if not want_itsm and current["require_itsm_approval"]:
            effects.append("Provisions and deploys no longer wait for ITSM approval.")
        effects.append(
            "Global: it applies to every user and integration of this Catalyst Center, not only this server."
        )
        plan = Plan(
            "Set provisioning settings: " + ", ".join(f"{k}={str(v).lower()}" for k, v in target.items()),
            details={
                "current": current,
                "target": target,
                "request": {"method": "PUT", "path": PATH, "body": body},
                "affected_tools": GATED_TOOLS,
                "effects": effects,
            },
            fingerprint={"settings": current},
            blockers=blockers,
            blast_unknown="a global Catalyst Center setting: it changes how every provisioning flow behaves, "
            "not a countable set of devices",
            noop=target == current,
            noop_reason=(
                f"Provisioning settings already require_preview={str(want_preview).lower()}, "
                f"require_itsm_approval={str(want_itsm).lower()}"
            )
            if target == current
            else None,
        )

        async def apply() -> Any:
            job = await app.run_job("PUT", PATH, body, ctx=ctx, what="provisioning settings")
            now = await read_settings(app)
            out: dict[str, Any] = {**now, "meaning": explain(now)}
            if job.get("task_id"):
                out["task_id"] = job["task_id"]
            if now != target:
                out["warning"] = f"Catalyst Center reports {now} after the change, not {target}."
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_set_provisioning_settings",
            args={"require_preview": require_preview, "require_itsm_approval": require_itsm_approval},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
