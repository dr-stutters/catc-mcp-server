"""Software image management (SWIM): image repository, per-device image status, golden tagging."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
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
from stutters_mcp_core.http import fetch_all

from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, is_uuid, pick, resolve_site

ROLES = Literal["ALL", "ACCESS", "DISTRIBUTION", "CORE", "BORDER ROUTER", "UNKNOWN"]


async def resolve_image(app: CatcApp, ref: str) -> dict[str, Any]:
    ref = ref.strip()
    params = {"imported": "true"}
    found = ensure_list(await app.get_response("/dna/intent/api/v1/images", {**params, "name": ref}))
    for img in found:
        if isinstance(img, dict) and (
            img.get("id") == ref or str(img.get("name", "")).lower() == ref.lower()
        ):
            return img
    if is_uuid(ref):
        page = await fetch_all(app.pager, app.api, "/dna/intent/api/v1/images", params, cap=2000)
        for img in page.items:
            if isinstance(img, dict) and img.get("id") == ref:
                return img
    raise NotFound(f"No imported software image {ref!r}. Use catc_list_images(imported=true).")


IMAGE_FIELDS = [
    "name",
    "version",
    "productNames",
    "imported",
    "golden",
    "recommended",
    "integrityStatus",
    "isAddonImage",
    "imageType",
    "id",
]


async def golden_state(
    app: CatcApp, image_id: str, site: dict[str, Any], product_ordinal: Any, roles: list[str]
) -> dict[str, Any]:
    """{role: {taggedGolden, inherited_from, tagged_here} | "unknown: ..."} for the preview."""
    site_id = "-1" if str(site.get("nameHierarchy", "")).lower() == "global" else str(site["id"])
    out: dict[str, Any] = {}
    for role in roles:
        path = (
            f"/dna/intent/api/v1/image/importation/golden/site/{site_id}/family/{product_ordinal}"
            f"/role/{quote(role)}/image/{image_id}"
        )
        try:
            st = await app.get_response(path)
        except UpstreamError as e:
            out[role] = f"unknown: {str(e)[:120]}"
            continue
        st = st if isinstance(st, dict) else {}
        inherited = st.get("inheritedSiteId")
        out[role] = {
            "taggedGolden": bool(st.get("taggedGolden")),
            "inherited_from": st.get("inheritedSiteName") if inherited and inherited != site_id else None,
            "tagged_here": bool(st.get("taggedGolden")) and (not inherited or inherited == site_id),
        }
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List software images")
    async def catc_list_images(
        ctx: Context,
        name: Annotated[str | None, Field(description="Image name contains (min 3 characters)")] = None,
        version: Annotated[
            str | None, Field(description="Version contains (min 3 characters), e.g. '17.9'")
        ] = None,
        golden: Annotated[
            bool | None, Field(description="true: only golden-tagged images; false: only untagged")
        ] = None,
        imported: Annotated[
            bool | None, Field(description="true: only images imported into the repository")
        ] = None,
        site: Annotated[
            str | None, Field(description="Site whose golden tagging to evaluate (default Global)")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Software images known to Catalyst Center (imported into the repository, or suggested from
        cisco.com): name, version, product families, golden tag, integrity status and id. Use
        golden=true to see the golden images per site."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {}
        if name:
            params["name"] = name
        if version:
            params["version"] = version
        if golden is not None:
            params["golden"] = str(golden).lower()
        if imported is not None:
            params["imported"] = str(imported).lower()
        if site:
            params["siteId"] = (await resolve_site(app, site))["id"]
        page = await app.pager.fetch_page(
            app.api, "/dna/intent/api/v1/images", params, limit=limit, offset=offset
        )
        page.items = [pick(i, IMAGE_FIELDS) or i for i in page.items if isinstance(i, dict)]
        return list_result(page, fmt=response_format)

    @reg.read(title="List device image status")
    async def catc_list_device_images(
        ctx: Context,
        site: Annotated[
            str | None, Field(description="Only devices at this site (id or name hierarchy)")
        ] = None,
        image_status: Annotated[
            Literal["COMPLIANT", "NON_COMPLIANT", "UNKNOWN"] | None,
            Field(description="Golden-image compliance: running the site's golden image or not"),
        ] = None,
        update_status: Annotated[
            Literal["IN_PROGRESS", "SUCCESS", "FAILURE", "UNKNOWN"] | None,
            Field(description="Status of the last distribution/activation"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Software image status per network device: the image it runs, whether that matches the
        golden image for its site and role (COMPLIANT / NON_COMPLIANT / UNKNOWN when no golden image is
        set), compatibility, and the status of the last image update. Use it to plan upgrades: tag a
        golden image (catc_tag_golden_image), then distribute and activate it."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {}
        if site:
            params["siteId"] = (await resolve_site(app, site))["id"]
        if image_status:
            params["networkDeviceImageStatus"] = image_status
        if update_status:
            params["networkDeviceUpdateStatus"] = update_status
        page = await app.pager.fetch_page(
            app.api, "/dna/intent/api/v1/networkDeviceImages", params, limit=limit, offset=offset
        )
        ids = [str(d.get("id")) for d in page.items if isinstance(d, dict) and d.get("id")]
        names: dict[str, Any] = {}
        if ids:
            devs = ensure_list(
                await app.get_response("/dna/intent/api/v1/network-device", {"id": ",".join(ids[:100])})
            )
            names = {str(d.get("id")): d.get("hostname") for d in devs if isinstance(d, dict)}
        rows = []
        for d in page.items:
            if not isinstance(d, dict):
                continue
            installed = [
                str(i.get("name")) for i in ensure_list(d.get("installedImages")) if isinstance(i, dict)
            ]
            rows.append(
                {
                    "hostname": names.get(str(d.get("id"))),
                    "managementAddress": d.get("managementAddress"),
                    "product": (d.get("networkDevice") or {}).get("productName"),
                    "running": ", ".join(installed),
                    "golden_status": d.get("networkDeviceImageStatus"),
                    "update_status": d.get("networkDeviceUpdateStatus"),
                    "compatibility": d.get("networkDeviceImageCompatibilityStatus"),
                    "id": d.get("id"),
                }
            )
        page.items = rows
        return list_result(page, fmt=response_format)

    @reg.write(title="Tag golden image", destructive=False)
    async def catc_tag_golden_image(
        ctx: Context,
        image: Annotated[
            str, Field(description="Imported image name or id (catc_list_images imported=true)")
        ],
        site: Annotated[
            str, Field(description="Site the tag applies to (inherited below); default Global")
        ] = "Global",
        product: Annotated[
            str | None,
            Field(
                description="Device product the image is golden for (name, e.g. 'Cisco Catalyst 9300 "
                "Switch', "
                "or productNameOrdinal); default: the image's only product"
            ),
        ] = None,
        device_roles: Annotated[
            list[ROLES] | None, Field(description="Device roles it applies to (default ALL)")
        ] = None,
        untag: Annotated[bool, Field(description="Remove the golden tag instead of setting it")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Mark an imported software image as golden (the target version) for a device product at a
        site and its children, or remove the tag. Devices whose running image differs then show as
        NON_COMPLIANT in catc_list_device_images and can be upgraded with catc_distribute_image /
        catc_activate_image. Preview-first; changes no device."""
        app: CatcApp = get_client(ctx)
        img = await resolve_image(app, image)
        s = await resolve_site(app, site)
        iid = safe_id(str(img["id"]), "image id")
        products = [
            p
            for p in (
                await fetch_all(
                    app.pager, app.api, f"/dna/intent/api/v1/images/{iid}/siteWiseProductNames", cap=500
                )
            ).items
            if isinstance(p, dict)
        ]
        if product:
            chosen = [
                p
                for p in products
                if str(p.get("productNameOrdinal")) == product.strip()
                or str(p.get("productName", "")).lower() == product.strip().lower()
            ]
        else:
            chosen = products
        if len(chosen) != 1:
            names = ", ".join(f"{p.get('productName')} ({p.get('productNameOrdinal')})" for p in products)
            if not products:
                raise NotFound(
                    f"Image {img.get('name')} has no device products assigned (Design > Image Repository)."
                )
            raise InvalidRequest(f"Pick one `product` for image {img.get('name')}: {names}.")
        prod = chosen[0]
        roles = list(device_roles or ["ALL"])
        body = {"productNameOrdinal": prod.get("productNameOrdinal"), "deviceRoles": roles}
        action = "untagGolden" if untag else "tagGolden"
        path = f"/dna/intent/api/v1/images/{iid}/sites/{s['id']}/{action}"
        current = await golden_state(app, iid, s, prod.get("productNameOrdinal"), roles)
        here = [r for r, st in current.items() if isinstance(st, dict) and st.get("tagged_here")]
        anywhere = [r for r, st in current.items() if isinstance(st, dict) and st.get("taggedGolden")]
        blockers = []
        if not untag and roles and set(here) == set(roles):
            blockers.append(f"Already golden at {s.get('nameHierarchy')} for roles {', '.join(roles)}.")
        if untag and roles and len(current) == len(roles) and not anywhere:
            blockers.append(f"Not golden at {s.get('nameHierarchy')} for roles {', '.join(roles)}.")
        plan = Plan(
            f"{'Remove golden tag from' if untag else 'Tag as golden'} {img.get('name')} for "
            f"{prod.get('productName')} at {s.get('nameHierarchy')} (roles {', '.join(roles)})",
            details={
                "image": pick(img, ["name", "version", "id"]),
                "method": "POST",
                "path": path,
                "body": body,
                "current_golden_state": current,
            },
            fingerprint={"image": img.get("id"), "golden": img.get("golden"), "state": current},
            blockers=blockers,
        )

        async def apply() -> Any:
            return await app.run_job("POST", path, body, ctx=ctx, what="golden tag")

        return await preview_or_apply(
            ctx,
            tool="catc_tag_golden_image",
            args={
                "image": image,
                "site": site,
                "product": product,
                "device_roles": device_roles,
                "untag": untag,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
