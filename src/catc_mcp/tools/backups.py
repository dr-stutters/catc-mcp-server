"""Catalyst Center system backups (roadmap D114): the backups on the target, the backup target itself and
the backup/restore executions, and an on-demand backup before a risky change (the group-based policy
migration, D108 #193).

The system backup API (`/dna/system/api/v1/backup*`, 3.2.2) needs a backup target: an NFS server or a
physical disk, chosen under System > Backup & Restore. Without one `GET backupConfiguration` answers an
empty record (`type: ""`, `mountPath: ""`; seen on the lab appliance, 2026-10-22) and a backup has nowhere
to go, so `catc_create_backup` refuses in its preview. `POST backups` answers a `taskId` that is a
backup/restore *execution* id (polled on `backupRestoreExecutions/{id}`), not an Intent API task.

Reads work with System.System Administration Read (the read-only role has it). Taking a backup is a
System Administration write, and on 3.2.2 that permission's maximum for a custom role is Read: Catalyst
Center lets only SUPER-ADMIN-ROLE back up and restore (docs/least-privilege.md).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    AuthError,
    Confirm,
    Plan,
    ResponseFormat,
    TaskFailed,
    ToolRegistrar,
    UpstreamError,
    UpstreamTimeout,
    get_client,
    list_result,
    object_result,
    poll_until,
    preview_or_apply,
)
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, gather_sections, pick

SYS = "/dna/system/api/v1"
SCOPES = {False: "CISCO_DNA_DATA_WITHOUT_ASSURANCE", True: "CISCO_DNA_DATA_WITH_ASSURANCE"}
BACKUP_FIELDS = [
    "name",
    "status",
    "scope",
    "startDate",
    "endDate",
    "duration",
    "size",
    "isBackupAvailable",
    "isCompatible",
    "releaseDisplayVersion",
    "createdBy",
    "id",
]
EXEC_FIELDS = [
    "jobType",
    "status",
    "completedPercentage",
    "scope",
    "startDate",
    "endDate",
    "duration",
    "createdBy",
    "errorCode",
    "errorMessage",
    "systemErrorMessage",
    "backupId",
    "id",
]
TASK_FIELDS = ["taskName", "status", "startDate", "endDate", "message", "errorCode", "systemErrorMessage"]
NO_TARGET = (
    "No backup target is configured on Catalyst Center: GET backupConfiguration has no storage type or mount "
    "path. Configure one under System > Backup & Restore (an NFS server or a physical disk, the number of "
    "backups to keep and an encryption passphrase), check it with catc_get_backup_status, then preview again."
)
DENIED = (
    "Catalyst Center refused the backup (403). Taking a backup needs System Administration Write, which "
    "3.2.2 gives only to SUPER-ADMIN-ROLE (a custom role's maximum is Read): run catc_create_backup from an "
    "instance whose account has SUPER-ADMIN-ROLE, only while you need it, or start the backup in the GUI "
    "(System > Backup & Restore). See docs/least-privilege.md."
)
# A backup copies every database to the target: give a waiting call at least an hour.
WAIT_FLOOR = 3600.0


def backup_row(b: dict[str, Any]) -> dict[str, Any]:
    row = pick(b, BACKUP_FIELDS)
    kind = (b.get("context") or {}).get("type") if isinstance(b.get("context"), dict) else None
    if kind:
        row["trigger"] = kind  # on-demand or scheduled
    if b.get("compatibilityError"):
        row["compatibility_errors"] = len(ensure_list(b["compatibilityError"]))
    return row


def exec_row(e: dict[str, Any], *, tasks: bool = False) -> dict[str, Any]:
    row = pick(e, EXEC_FIELDS)
    steps = [t for t in ensure_list(e.get("tasks")) if isinstance(t, dict)]
    if tasks and steps:
        row["tasks"] = [pick(t, TASK_FIELDS) for t in steps]
    failed = [str(t.get("taskName")) for t in steps if str(t.get("status", "")).upper() == "FAILED"]
    if failed:
        row["failed_tasks"] = failed
    return row


async def backup_target(app: CatcApp) -> tuple[dict[str, Any], list[str]]:
    """The configured backup target ({"configured": bool, ...} with the NFS server's health and the storage
    use when Catalyst Center reports them) and the reasons a backup can't run now."""
    cfg = await app.get_response(f"{SYS}/backupConfiguration")
    cfg = cfg if isinstance(cfg, dict) else {}
    kind = str(cfg.get("type") or "")
    mount = str(cfg.get("mountPath") or "")
    if not kind or not mount:
        return {"configured": False}, [NO_TARGET]
    target: dict[str, Any] = {
        "configured": True,
        "type": kind,
        "mount_path": mount,
        "backups_kept": cfg.get("dataRetention"),
        "encryption_passphrase_set": cfg.get("isEncryptionPassPhraseAvailable"),
    }
    blockers: list[str] = []
    if cfg.get("isEncryptionPassPhraseAvailable") is False:
        blockers.append(
            "The backup configuration has no encryption passphrase; Catalyst Center encrypts every backup "
            "with it. Set it under System > Backup & Restore > Configure, then preview again."
        )
    sections: dict[str, Any] = {
        "storage": app.get_response(f"{SYS}/backupStorages", {"storageType": kind}),
    }
    if kind.upper() == "NFS":
        sections["nfs"] = app.get_response(f"{SYS}/backupNfsConfigurations")
    data, errors = await gather_sections(sections)
    disk = next(
        (
            s
            for s in ensure_list(data.get("storage"))
            if isinstance(s, dict) and str(s.get("mountPoint") or "") == mount
        ),
        None,
    )
    if disk:
        target["storage"] = pick(disk, ["diskName", "fstype", "percentUsage", "usedSize", "totalSize"])
    nfs = [n for n in ensure_list(data.get("nfs")) if isinstance(n, dict)]
    if nfs:
        target["nfs_servers"] = [
            {
                **pick(n.get("spec") or {}, ["server", "sourcePath", "nfsVersion"]),
                **pick(n.get("status") or {}, ["state", "destinationPath", "subResourceState"]),
                "id": n.get("id"),
            }
            for n in nfs
        ]
        mine = [n for n in nfs if str((n.get("status") or {}).get("destinationPath") or "") == mount]
        bad = [n for n in mine if str((n.get("status") or {}).get("state") or "").lower() == "unhealthy"]
        if bad:
            st = bad[0].get("status") or {}
            blockers.append(
                f"The NFS backup server behind {mount} is UnHealthy"
                + (f" ({st.get('subResourceState')})" if st.get("subResourceState") else "")
                + ": fix the NFS export or the network path, then preview again."
            )
    if errors:
        target["unavailable"] = errors
    return target, blockers


def exec_finished(e: dict[str, Any]) -> bool:
    return str(e.get("status", "")).upper() in ("SUCCESS", "FAILED")


def exec_failed(e: dict[str, Any]) -> str | bool:
    if str(e.get("status", "")).upper() != "FAILED":
        return False
    steps = [t for t in ensure_list(e.get("tasks")) if isinstance(t, dict)]
    step = next((t for t in steps if str(t.get("status", "")).upper() == "FAILED"), None)
    reason = e.get("errorMessage") or e.get("systemErrorMessage") or "status FAILED"
    return str(reason) + (f" (step {step.get('taskName')}: {step.get('message')})" if step else "")


async def running_executions(app: CatcApp) -> list[dict[str, Any]]:
    rows = await app.get_response(f"{SYS}/backupRestoreExecutions", {"status": "IN_PROGRESS", "limit": 10})
    return [r for r in ensure_list(rows) if isinstance(r, dict)]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List backups")
    async def catc_list_backups(
        ctx: Context,
        query: Annotated[
            str | None, Field(description="Catalyst Center's text filter on the backup fields (e.g. a name)")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=50)] = 20,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Catalyst Center system backups on the configured backup target, newest first: name, status
        (SUCCESS, FAILED, IN_PROGRESS), scope (with or without Assurance data), start/end, duration, size,
        whether it is still on the target and compatible to restore, the release it was taken on, who
        took it and whether it was on-demand or scheduled. Says so when no backup target is configured.
        The target, the passphrase and running jobs: catc_get_backup_status."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {"sortBy": "startDate", "order": "desc"}
        if query:
            params["query"] = query
        page = await app.data_pager.fetch_page(
            app.api, f"{SYS}/backups", params, limit=limit, offset=offset, max_page=50
        )
        page.items = [backup_row(b) for b in page.items if isinstance(b, dict)]
        extra: dict[str, Any] | None = None
        if not page.items and offset == 0 and not query:
            target, _ = await backup_target(app)
            extra = {
                "note": "No backups."
                + ("" if target.get("configured") else " " + NO_TARGET.split(":")[0] + ".")
            }
        return list_result(
            page,
            fmt=response_format,
            columns=["name", "status", "scope", "startDate", "duration", "size", "isCompatible", "id"],
            extra=extra,
        )

    @reg.read(title="Backup status")
    async def catc_get_backup_status(
        ctx: Context,
        execution: Annotated[
            str | None,
            Field(
                description="One backup/restore execution id (catc_create_backup returns it): its progress "
                "and every step"
            ),
        ] = None,
        recent: Annotated[
            int, Field(ge=1, le=25, description="How many recent backup/restore executions to list")
        ] = 5,
    ) -> ToolResult:
        """Whether Catalyst Center can take a backup now, and how the last ones went: the backup target
        (NFS server or physical disk, mount path, backups kept, encryption passphrase set, the NFS
        server's health and the disk use), `ready` with the blockers (no target, no passphrase, NFS
        unhealthy, a backup or restore already running), the last backup, and the recent backup/restore
        executions (job, status, percent done, errors). With `execution`: that execution's progress and
        steps, e.g. a backup catc_create_backup started without waiting. Use it before the group-based
        policy migration or an upgrade."""
        app: CatcApp = get_client(ctx)
        if execution:
            e = await app.get_response(f"{SYS}/backupRestoreExecutions/{safe_id(execution, 'execution id')}")
            return object_result(exec_row(e if isinstance(e, dict) else {}, tasks=True))
        data, errors = await gather_sections(
            {
                "target": backup_target(app),
                "last": app.get_response(
                    f"{SYS}/backups", {"limit": 1, "sortBy": "startDate", "order": "desc"}
                ),
                "executions": app.get_response(f"{SYS}/backupRestoreExecutions", {"limit": recent}),
            }
        )
        out: dict[str, Any] = {}
        blockers: list[str] = []
        if "target" in data:
            out["target"], blockers = data["target"]
        execs = [e for e in ensure_list(data.get("executions")) if isinstance(e, dict)]
        running = [e for e in execs if str(e.get("status", "")).upper() == "IN_PROGRESS"]
        if running:
            blockers.append(
                f"A {running[0].get('jobType') or 'backup/restore'} is already running "
                f"({running[0].get('completedPercentage', '?')}% done, execution {running[0].get('id')})."
            )
        if "target" in data:
            out["ready"] = not blockers
            out["blockers"] = blockers
        if "last" in data:
            last = [b for b in ensure_list(data["last"]) if isinstance(b, dict)]
            out["last_backup"] = backup_row(last[0]) if last else "no backups taken"
        if "executions" in data:
            out["recent_executions"] = [exec_row(e) for e in execs] or "none"
        if errors:
            out["unavailable"] = errors
        return object_result(out)

    @reg.dangerous(title="Create backup", task=True)
    async def catc_create_backup(
        ctx: Context,
        name: Annotated[
            str,
            Field(
                min_length=1,
                max_length=64,
                pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
                description="Backup name: letters, digits, '.', '_' and '-', e.g. 'pre-gbp-migration'",
            ),
        ],
        include_assurance: Annotated[
            bool,
            Field(
                description="Also back up Assurance data (much larger and slower); default false backs up "
                "the automation data: design, inventory, policy, templates, settings"
            ),
        ] = False,
        wait: Annotated[
            bool,
            Field(
                description="Wait for the backup to finish (it can take an hour or more). Default false: "
                "returns the execution id; follow it with catc_get_backup_status(execution=...)"
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Take an on-demand Catalyst Center system backup to the configured backup target (NFS server or
        physical disk), e.g. before the group-based policy migration or an upgrade. Refused in the preview
        when no backup target is configured, the configuration has no encryption passphrase, the NFS
        server is unhealthy, a backup or restore is already running, or a backup with that name exists.
        Preview-first: the preview shows the target, the scope and the last backup. Needs a SUPER-ADMIN-ROLE
        account (custom roles get 403). Restoring is not automated: restore from System > Backup & Restore."""
        app: CatcApp = get_client(ctx)
        target, blockers = await backup_target(app)
        scope = SCOPES[include_assurance]
        running: list[dict[str, Any]] = []
        last: dict[str, Any] | None = None
        taken = False
        if target.get("configured"):
            running = await running_executions(app)
            if running:
                r = running[0]
                blockers.append(
                    f"A {r.get('jobType') or 'backup/restore'} is already running "
                    f"({r.get('completedPercentage', '?')}% done, execution {r.get('id')}); Catalyst Center "
                    "runs one at a time. Wait for it (catc_get_backup_status)."
                )
            backups = [
                b
                for b in (
                    await fetch_all(
                        app.data_pager,
                        app.api,
                        f"{SYS}/backups",
                        {"sortBy": "startDate", "order": "desc"},
                        cap=500,
                        max_page=50,
                    )
                ).items
                if isinstance(b, dict)
            ]
            last = backup_row(backups[0]) if backups else None
            taken = any(str(b.get("name")) == name for b in backups)
            if taken:
                blockers.append(f"A backup named {name!r} already exists; pick another name.")
        details: dict[str, Any] = {
            "target": target,
            "scope": scope,
            "last_backup": last or "none",
            "method": "POST",
            "path": f"{SYS}/backups",
            "body": {"name": name, "scope": scope},
        }
        try:
            tiers = await app.role_tiers() if app.settings.username else None
        except UpstreamError:
            tiers = None
        if tiers and "admin" not in tiers.values():
            details["account_warning"] = (
                f"The account's roles ({', '.join(sorted(tiers))}) are not SUPER-ADMIN-ROLE: Catalyst Center "
                "3.2.2 lets only SUPER-ADMIN-ROLE take backups, so expect 403."
            )
        plan = Plan(
            f"Back up Catalyst Center as {name!r} ("
            + ("with" if include_assurance else "without")
            + " Assurance data)"
            + (f" to {target.get('type')} {target.get('mount_path')}" if target.get("configured") else ""),
            details=details,
            side_effects=[
                "Catalyst Center copies its databases and files to the backup target; it keeps running, "
                "but the appliance is busier until the backup finishes.",
                f"Catalyst Center keeps {target.get('backups_kept')} backup(s) on the target and may remove "
                "the oldest one."
                if target.get("backups_kept")
                else "Older backups on the target are kept or pruned as the backup configuration says.",
                "Nothing changes on the network devices.",
            ],
            fingerprint={
                "target": {k: target.get(k) for k in ("type", "mount_path")},
                "running": sorted(str(r.get("id")) for r in running),
                "name_taken": taken,
            },
            blockers=blockers,
        )

        async def apply() -> Any:
            try:
                started = await app.api.post(f"{SYS}/backups", {"name": name, "scope": scope})
            except AuthError as denied:
                raise AuthError(DENIED, status_code=denied.status_code) from denied
            ref = started.get("response") if isinstance(started, dict) else None
            exec_id = str(ref.get("taskId") or "") if isinstance(ref, dict) else ""
            if not exec_id:
                return {"started": started, "check_with": "catc_get_backup_status"}
            check = f"catc_get_backup_status(execution='{exec_id}')"
            if not wait:
                return {"execution_id": exec_id, "status": "IN_PROGRESS", "check_with": check}
            path = f"{SYS}/backupRestoreExecutions/{safe_id(exec_id, 'execution id')}"

            async def fetch() -> dict[str, Any]:
                got = await app.get_response(path)
                return got if isinstance(got, dict) else {}

            try:
                run = await poll_until(
                    fetch,
                    done=exec_finished,
                    failed=exec_failed,
                    describe=lambda r: f"{r.get('status')} {r.get('completedPercentage', '?')}%",
                    timeout=max(app.settings.mcp_task_timeout, WAIT_FLOOR),
                    interval=10.0,
                    max_interval=60.0,
                    ctx=ctx,
                    what="backup",
                )
            except (TaskFailed, UpstreamTimeout) as err:
                raise type(err)(f"{err} Check it with {check}.") from err
            out: dict[str, Any] = {"execution_id": exec_id, **exec_row(run)}
            if bid := run.get("backupId"):
                try:
                    b = await app.get_response(f"{SYS}/backups/{safe_id(str(bid), 'backup id')}")
                    if isinstance(b, dict):
                        out["backup"] = backup_row(b)
                except UpstreamError as err:
                    out["backup"] = {"unavailable": str(err)[:200]}
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_create_backup",
            args={"name": name, "include_assurance": include_assurance, "wait": wait},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
