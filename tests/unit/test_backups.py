"""D114: Catalyst Center system backups (respx). The empty answers (no target, no backups, no executions) are
the 3.2.2 lab appliance's live ones (2026-10-22, read as mcp-catc-rw); the configured target, backups and
executions follow the 3.2.2 spec."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp import rbac
from catc_mcp.server import create_server
from catc_mcp.tools.backups import NO_TARGET, exec_failed

from .conftest import make_settings
from .test_read_tools import call
from .test_write_tools import run

SYS = "/dna/system/api/v1"
EXEC_ID = "eeeeeeee-1111-2222-3333-444444444444"
BACKUP_ID = "bbbbbbbb-1111-2222-3333-444444444444"
PAGE = {"limit": 50, "offset": 1, "count": 0, "sortBy": [{"name": "startDate", "order": "desc"}]}
# Live, 2026-10-22: no backup target configured.
EMPTY_CONFIG = {
    "version": "2.0",
    "response": {
        "type": "",
        "dataRetention": 0,
        "mountPath": "",
        "id": "",
        "isEncryptionPassPhraseAvailable": False,
    },
}
NFS_CONFIG = {
    "version": "2.0",
    "response": {
        "type": "NFS",
        "dataRetention": 3,
        "mountPath": "/data/nfs/backup-1",
        "id": "cfg-1",
        "isEncryptionPassPhraseAvailable": True,
    },
}
NFS = {
    "id": "nfs-1",
    "spec": {"server": "198.18.133.50", "sourcePath": "/srv/catc", "nfsVersion": "nfs4", "nfsPort": 2049},
    "status": {"state": "Healthy", "destinationPath": "/data/nfs/backup-1"},
}
BACKUP = {
    "id": BACKUP_ID,
    "name": "nightly-1",
    "status": "SUCCESS",
    "scope": "CISCO_DNA_DATA_WITHOUT_ASSURANCE",
    "startDate": "2026-10-21T02:00:00Z",
    "endDate": "2026-10-21T02:41:00Z",
    "duration": 2460,
    "size": 21474836480,
    "isBackupAvailable": True,
    "isCompatible": True,
    "releaseDisplayVersion": "3.2.2",
    "createdBy": "admin",
    "context": {"type": "SCHEDULED", "schedule": "daily"},
    "installedPackages": [{"name": "sda", "version": "3.2.2"}],
}


def lab(
    api: respx.MockRouter,
    *,
    config: dict[str, Any] = NFS_CONFIG,
    nfs: list[dict[str, Any]] | None = None,
    backups: list[dict[str, Any]] | None = None,
    running: list[dict[str, Any]] | None = None,
) -> respx.Route:
    api.get(f"{SYS}/backupConfiguration").respond(json=config)
    api.get(f"{SYS}/backupNfsConfigurations").respond(json={"version": "2.0", "response": nfs or []})
    api.get(f"{SYS}/backupStorages").respond(
        json={
            "version": "2.0",
            "response": [{"mountPoint": "/data/nfs/backup-1", "fstype": "nfs4", "percentUsage": 41.5}]
            if config is NFS_CONFIG
            else [],
        }
    )
    rows = backups or []
    listed = api.get(f"{SYS}/backups").respond(
        json={"version": "2.0", "response": rows, "page": {**PAGE, "count": len(rows)}, "filter": {}}
    )

    def executions(request: httpx.Request) -> httpx.Response:
        rows = running or []
        if request.url.params.get("status") == "IN_PROGRESS":
            rows = [r for r in rows if r.get("status") == "IN_PROGRESS"]
        return httpx.Response(
            200, json={"version": "2.0", "response": rows, "page": {**PAGE, "count": len(rows)}}
        )

    api.get(f"{SYS}/backupRestoreExecutions").mock(side_effect=executions)
    return listed


async def flow(args: dict[str, Any], **settings: Any) -> tuple[dict[str, Any], dict[str, Any] | None]:
    server = create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, **settings))
    async with Client(server) as c:
        preview = await run(c, "catc_create_backup", args)
        if preview.get("status") != "preview":
            return preview, None
        return preview, await run(c, "catc_create_backup", {**args, "confirm": preview["confirm"]})


# --- reads ----------------------------------------------------------------------------------------


async def test_list_backups(api: respx.MockRouter) -> None:
    listed = lab(api, backups=[BACKUP])
    out = await call("catc_list_backups", {"response_format": "json"})
    row = out["results"][0]
    assert row["name"] == "nightly-1" and row["status"] == "SUCCESS" and row["trigger"] == "SCHEDULED"
    assert "installedPackages" not in row and out["total"] == 1
    q = listed.calls.last.request.url.params
    assert q["offset"] == "1" and q["sortBy"] == "startDate" and q["order"] == "desc"  # 1-based offset


async def test_list_backups_says_no_target(api: respx.MockRouter) -> None:
    lab(api, config=EMPTY_CONFIG)
    out = await call("catc_list_backups", {"response_format": "json"})
    assert out["results"] == [] and "No backup target is configured" in out["note"]


async def test_status_without_target(api: respx.MockRouter) -> None:
    """The lab appliance's answer on 2026-10-22: nothing configured, nothing taken."""
    lab(api, config=EMPTY_CONFIG)
    out = await call("catc_get_backup_status")
    assert out["target"] == {"configured": False} and out["ready"] is False
    assert out["blockers"] == [NO_TARGET]
    assert out["last_backup"] == "no backups taken" and out["recent_executions"] == "none"


async def test_status_ready_on_nfs(api: respx.MockRouter) -> None:
    lab(api, nfs=[NFS], backups=[BACKUP])
    out = await call("catc_get_backup_status")
    assert out["ready"] is True and "blockers" not in out  # compact() drops the empty list
    t = out["target"]
    assert t["type"] == "NFS" and t["mount_path"] == "/data/nfs/backup-1" and t["backups_kept"] == 3
    assert t["encryption_passphrase_set"] is True and t["storage"]["percentUsage"] == 41.5
    assert t["nfs_servers"][0]["server"] == "198.18.133.50" and t["nfs_servers"][0]["state"] == "Healthy"
    assert out["last_backup"]["name"] == "nightly-1"


async def test_status_flags_running_job_and_unhealthy_nfs(api: respx.MockRouter) -> None:
    sick = {**NFS, "status": {**NFS["status"], "state": "UnHealthy", "subResourceState": "mount timed out"}}
    job = {"id": EXEC_ID, "jobType": "CREATE_BACKUP", "status": "IN_PROGRESS", "completedPercentage": 40}
    lab(api, nfs=[sick], running=[job])
    out = await call("catc_get_backup_status")
    assert out["ready"] is False and len(out["blockers"]) == 2
    assert "UnHealthy (mount timed out)" in out["blockers"][0]
    assert "CREATE_BACKUP is already running (40% done" in out["blockers"][1]


async def test_status_of_one_execution(api: respx.MockRouter) -> None:
    api.get(f"{SYS}/backupRestoreExecutions/{EXEC_ID}").respond(
        json={
            "version": "2.0",
            "response": {
                "id": EXEC_ID,
                "jobType": "CREATE_BACKUP",
                "status": "FAILED",
                "errorMessage": "Backup failed",
                "tasks": [
                    {"taskName": "precheck", "status": "SUCCESS"},
                    {"taskName": "copy-maglev", "status": "FAILED", "message": "No space left on device"},
                ],
            },
        }
    )
    out = await call("catc_get_backup_status", {"execution": EXEC_ID})
    assert out["status"] == "FAILED" and out["failed_tasks"] == ["copy-maglev"]
    assert out["tasks"][1]["message"] == "No space left on device"
    with pytest.raises(ToolError, match="Invalid execution id"):
        await call("catc_get_backup_status", {"execution": "../backups"})


# --- catc_create_backup ---------------------------------------------------------------------------


async def test_create_refuses_without_target(api: respx.MockRouter) -> None:
    lab(api, config=EMPTY_CONFIG)
    post = api.post(f"{SYS}/backups").respond(202, json={"response": {"taskId": EXEC_ID}})
    out, done = await flow({"name": "pre-gbp-migration"})
    assert out["status"] == "blocked" and done is None and not post.called
    assert out["blockers"] == [NO_TARGET]


async def test_create_preview_then_start(api: respx.MockRouter) -> None:
    lab(api, nfs=[NFS], backups=[BACKUP])
    post = api.post(f"{SYS}/backups").respond(
        202,
        json={
            "version": "2.0",
            "response": {"taskId": EXEC_ID, "url": f"/backupRestoreExecutions/{EXEC_ID}"},
        },
    )
    preview, done = await flow({"name": "pre-gbp-migration"})
    assert preview["action"] == (
        "Back up Catalyst Center as 'pre-gbp-migration' (without Assurance data) to NFS /data/nfs/backup-1"
    )
    assert preview["preview"]["scope"] == "CISCO_DNA_DATA_WITHOUT_ASSURANCE"
    assert preview["preview"]["last_backup"]["name"] == "nightly-1"
    assert "account_warning" not in preview["preview"]  # the fixture account is SUPER-ADMIN-ROLE
    assert any("keeps 3 backup(s)" in s for s in preview["side_effects"])
    assert post.call_count == 1 and done is not None
    assert json.loads(post.calls.last.request.content) == {
        "name": "pre-gbp-migration",
        "scope": "CISCO_DNA_DATA_WITHOUT_ASSURANCE",
    }
    assert done["result"] == {
        "execution_id": EXEC_ID,
        "status": "IN_PROGRESS",
        "check_with": f"catc_get_backup_status(execution='{EXEC_ID}')",
    }


async def test_create_waits_for_the_execution(api: respx.MockRouter) -> None:
    lab(api)
    api.post(f"{SYS}/backups").respond(202, json={"response": {"taskId": EXEC_ID}})
    api.get(f"{SYS}/backupRestoreExecutions/{EXEC_ID}").respond(
        json={
            "response": {
                "id": EXEC_ID,
                "jobType": "CREATE_BACKUP",
                "status": "SUCCESS",
                "completedPercentage": 100,
                "backupId": BACKUP_ID,
            }
        }
    )
    api.get(f"{SYS}/backups/{BACKUP_ID}").respond(json={"response": {**BACKUP, "name": "pre-gbp"}})
    _, done = await flow({"name": "pre-gbp", "include_assurance": True, "wait": True})
    assert done is not None
    res = done["result"]
    assert res["status"] == "SUCCESS" and res["backup"]["name"] == "pre-gbp"


async def test_create_failed_execution_names_the_step(api: respx.MockRouter) -> None:
    lab(api)
    api.post(f"{SYS}/backups").respond(202, json={"response": {"taskId": EXEC_ID}})
    api.get(f"{SYS}/backupRestoreExecutions/{EXEC_ID}").respond(
        json={
            "response": {
                "id": EXEC_ID,
                "status": "FAILED",
                "errorMessage": "Backup failed",
                "tasks": [{"taskName": "copy-maglev", "status": "FAILED", "message": "disk full"}],
            }
        }
    )
    with pytest.raises(ToolError, match=r"step copy-maglev: disk full.*catc_get_backup_status\(execution="):
        await flow({"name": "pre-gbp", "wait": True})


@pytest.mark.parametrize(
    ("setup", "blocker"),
    [
        (
            {"running": [{"id": EXEC_ID, "jobType": "RESTORE_BACKUP", "status": "IN_PROGRESS"}]},
            "RESTORE_BACKUP",
        ),
        ({"backups": [BACKUP]}, "A backup named 'nightly-1' already exists"),
        (
            {"config": {"response": {**NFS_CONFIG["response"], "isEncryptionPassPhraseAvailable": False}}},
            "no encryption passphrase",
        ),
        (
            {"nfs": [{**NFS, "status": {**NFS["status"], "state": "UnHealthy"}}]},
            "NFS backup server behind /data/nfs/backup-1 is UnHealthy",
        ),
    ],
)
async def test_create_blockers(api: respx.MockRouter, setup: dict[str, Any], blocker: str) -> None:
    lab(api, **setup)
    post = api.post(f"{SYS}/backups").respond(202, json={"response": {"taskId": EXEC_ID}})
    out, _ = await flow({"name": "nightly-1"})
    assert out["status"] == "blocked" and not post.called
    assert any(blocker in b for b in out["blockers"]), out["blockers"]


async def test_create_warns_custom_role_and_explains_403(api: respx.MockRouter) -> None:
    lab(api)
    api.get(f"{SYS}/user").respond(
        json={"response": {"users": [{"username": "mcp-catc-admin", "roleList": ["mcp-catc-dangerous"]}]}}
    )
    api.get("/dna/system/api/v2/roles/mcp-catc-dangerous").respond(
        json={
            "id": "mcp-catc-dangerous",
            "permissions": [{"id": k, "privilege": v} for k, v in rbac.DANGEROUS.items()],
        }
    )
    api.post(f"{SYS}/backups").respond(
        403, json={"message": "Role does not have valid permissions to access the API"}
    )
    with pytest.raises(ToolError, match="SUPER-ADMIN-ROLE") as err:
        await flow({"name": "pre-gbp"}, username="mcp-catc-admin")
    assert "docs/least-privilege.md" in str(err.value)
    server = create_server(
        make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, username="mcp-catc-admin")
    )
    async with Client(server) as c:
        preview = await run(c, "catc_create_backup", {"name": "pre-gbp"})
    assert "not SUPER-ADMIN-ROLE" in preview["preview"]["account_warning"]


def test_exec_failed() -> None:
    assert exec_failed({"status": "IN_PROGRESS"}) is False
    assert exec_failed({"status": "FAILED"}) == "status FAILED"
