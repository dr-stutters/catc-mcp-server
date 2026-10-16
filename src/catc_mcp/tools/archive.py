"""Configuration archive: the running/startup config versions Catalyst Center keeps per device, and
diffs between them (what changed, unsaved changes)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import difflib
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    InvalidRequest,
    NotFound,
    ResponseFormat,
    ToolRegistrar,
    get_client,
    list_result,
    object_result,
)
from catc_mcp._core.http import fetch_all, page_of
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ago, resolve_device
from catc_mcp.tools.inventory import DeviceRef, redact_config

ARCHIVE = "/dna/intent/api/v1/networkDeviceConfigFiles"
FileType = Literal["RUNNINGCONFIG", "STARTUPCONFIG", "VLAN"]


ARCHIVE_NOTE = (
    "Catalyst Center archives a new version a few minutes after a config change syslog (or after "
    "catc_resync_devices): a change newer than the 'to' version is not in this diff yet."
)


def _when(ms: Any) -> str | None:
    if not isinstance(ms, int | float):
        return None
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


async def archive_files(app: CatcApp, device_id: str, file_type: str | None = None) -> list[dict[str, Any]]:
    """Archived config files of one device, newest first."""
    params: dict[str, Any] = {"networkDeviceId": device_id}
    if file_type:
        params["fileType"] = file_type
    page = await fetch_all(app.pager, app.api, ARCHIVE, params, cap=2000)
    files = [f for f in page.items if isinstance(f, dict)]
    files.sort(key=lambda f: f.get("createdTime") or 0, reverse=True)
    return files


async def file_text(app: CatcApp, file_id: str) -> str:
    """A config file's text with secrets masked (Catalyst Center masks them; we mask again)."""
    data = await app.api.post(f"{ARCHIVE}/{safe_id(file_id, 'file id')}/downloadMasked")
    text = data if isinstance(data, str) else str(data or "")
    return redact_config(text)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List config archive")
    async def catc_list_config_archive(
        ctx: Context,
        device: DeviceRef,
        file_type: Annotated[FileType | None, Field(description="Only this kind of file")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Configuration versions Catalyst Center has archived for a device (running and startup
        config, VLAN database), newest first, with when and why each was taken (first collection,
        scheduled, config-change syslog, user request) and the file ids. Compare two with
        catc_compare_device_configs."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        rows = [
            {
                "created": _when(f.get("createdTime")),
                "fileType": f.get("fileType"),
                "createdBy": f.get("createdBy"),
                "versionId": f.get("versionId"),
                "id": f.get("id"),
            }
            for f in await archive_files(app, str(dev["id"]), file_type)
        ]
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            extra={"device": dev.get("hostname")},
        )

    @reg.read(title="Compare device configs")
    async def catc_compare_device_configs(
        ctx: Context,
        device: DeviceRef,
        compare: Annotated[
            Literal["previous", "startup", "files"],
            Field(
                description="'previous': latest running config vs the version before it (what changed); "
                "'startup': latest running vs latest startup config (unsaved changes); 'files': the two "
                "file ids given"
            ),
        ] = "previous",
        from_file: Annotated[
            str | None,
            Field(description="With compare='files': the older file id (catc_list_config_archive)"),
        ] = None,
        to_file: Annotated[str | None, Field(description="With compare='files': the newer file id")] = None,
        context_lines: Annotated[
            int, Field(ge=0, le=20, description="Unchanged lines around each change")
        ] = 3,
        max_lines: Annotated[
            int, Field(ge=10, le=5000, description="Truncate the diff after this many lines (default 400)")
        ] = 400,
    ) -> ToolResult:
        """Unified diff between two archived configurations of one device: what changed since the
        previous running config, what is unsaved (running vs startup), or any two archive files.
        Secrets are masked in both. Use it to find configuration drift and to confirm a template
        deploy landed. The archive only gets a new version when Catalyst Center collects one (config
        change syslog, schedule or resync), so very recent changes may not be there yet."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        did = str(dev["id"])
        if compare == "files":
            if not from_file or not to_file:
                raise InvalidRequest("compare='files' needs from_file and to_file.")
            files = {str(f.get("id")): f for f in await archive_files(app, did)}
            old, new = files.get(from_file.strip()), files.get(to_file.strip())
            if old is None or new is None:
                raise NotFound(
                    f"Both files must belong to {dev.get('hostname')}; see catc_list_config_archive."
                )
        else:
            running = await archive_files(app, did, "RUNNINGCONFIG")
            if not running:
                raise NotFound(f"No archived running config for {dev.get('hostname')} yet.")
            new = running[0]
            if compare == "previous":
                if len(running) < 2:
                    return object_result(
                        {
                            "device": dev.get("hostname"),
                            "note": "Only one running-config version is archived; nothing to compare yet.",
                            "latest": {
                                "id": new.get("id"),
                                "created": _when(new.get("createdTime")),
                                "age": ago(new.get("createdTime")),
                            },
                        }
                    )
                old = running[1]
            else:
                startup = await archive_files(app, did, "STARTUPCONFIG")
                if not startup:
                    raise NotFound(f"No archived startup config for {dev.get('hostname')}.")
                old = startup[0]
        old_text = await file_text(app, str(old["id"]))
        new_text = await file_text(app, str(new["id"]))

        def label(f: dict[str, Any]) -> str:
            return f"{f.get('fileType')} {_when(f.get('createdTime'))} ({f.get('id')})"

        diff = list(
            difflib.unified_diff(
                old_text.splitlines(),
                new_text.splitlines(),
                fromfile=label(old),
                tofile=label(new),
                n=context_lines,
                lineterm="",
            )
        )
        added = sum(1 for d in diff if d.startswith("+") and not d.startswith("+++"))
        removed = sum(1 for d in diff if d.startswith("-") and not d.startswith("---"))
        return object_result(
            {
                "device": dev.get("hostname"),
                "from": label(old),
                "to": label(new),
                "identical": not diff,
                "lines_added": added,
                "lines_removed": removed,
                "newest_version_age": ago(new.get("createdTime")),
                "archive_note": ARCHIVE_NOTE,
                "diff": "\n".join(diff[:max_lines]),
                **(
                    {"truncated": f"diff cut at {max_lines} of {len(diff)} lines; raise max_lines"}
                    if len(diff) > max_lines
                    else {}
                ),
            },
            shape=False,
        )
