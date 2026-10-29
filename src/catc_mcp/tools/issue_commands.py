"""D64: run an assurance issue's suggested commands (execute-suggested-actions-commands).

Catalyst Center's POST /dna/intent/api/v1/execute-suggested-actions-commands takes an issue id and runs
every command of the issue's suggested actions itself: the caller cannot pick or filter them. So the
issue is read first (the same data-API record catc_get_issue shows) and every suggested command is
checked against the command runner allow-list (show / ping / traceroute / dir, as for catc_run_show_commands
and catc_ping); one command outside it refuses the whole call before anything runs on a device.

The API answers 202 with an execution id (the business-API execution status then carries the result list
in bapiSyncResponse) or, on some releases, the list itself. Each row names the device (hostname,
entityId), the command and its commandOutput; the output is cleaned like the command runner's (echoed
command and trailing prompt dropped, secrets masked) and grouped per device.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import json
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    AuthError,
    InvalidRequest,
    NotFound,
    RateLimited,
    ToolRegistrar,
    Unreachable,
    UpstreamError,
    UpstreamTimeout,
    compact,
    get_client,
    object_result,
)
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list
from catc_mcp.tools.assurance import fetch_issue, is_device_issue, issue_row, suggested_actions
from catc_mcp.tools.device_probe import check_runner_command
from catc_mcp.tools.inventory import redact_config
from catc_mcp.tools.smart import clean_output, run_show

EXECUTE_PATH = "/dna/intent/api/v1/execute-suggested-actions-commands"
_RUNNER_KEYS = ("SUCCESS", "FAILURE", "BLACKLISTED")
NO_FALLBACK = (AuthError, RateLimited, Unreachable, UpstreamTimeout)


def issue_commands(actions: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """(allowed, refused): the issue's suggested commands, each once, in order, split by the allow-list."""
    allowed: list[str] = []
    refused: list[str] = []
    for a in actions:
        for cmd in a.get("commands") or []:
            try:
                c = check_runner_command(cmd)
            except InvalidRequest:
                if cmd not in refused:
                    refused.append(cmd)
                continue
            if c not in allowed:
                allowed.append(c)
    return allowed, refused


def _text(command: str, raw: Any) -> str:
    if isinstance(raw, dict | list):
        raw = json.dumps(raw)
    return redact_config(clean_output(command, str(raw))) or "(no output)"


def result_rows(data: Any) -> list[dict[str, Any]]:
    """The per-command rows, from a bare list, a {"response": [...]} envelope or an execution summary."""
    if isinstance(data, dict):
        for key in ("bapiSyncResponse", "response", "result"):
            if key in data:
                return result_rows(data[key])
        return [data] if "command" in data or "commandOutput" in data else []
    if isinstance(data, str) and data.startswith(("[", "{")):
        try:
            return result_rows(json.loads(data))
        except ValueError:
            return []
    return [r for r in ensure_list(data) if isinstance(r, dict)]


def group_results(rows: list[dict[str, Any]], issue_device: str | None) -> list[dict[str, Any]]:
    """One entry per device: output per command (cleaned, secrets masked) and the commands that failed."""
    merged: dict[str, dict[str, Any]] = {}
    for r in rows:
        device = str(r.get("hostname") or r.get("entityId") or issue_device or "unknown")
        entry = merged.setdefault(device, {"device": device, "output": {}})
        cmd = " ".join(str(r.get("command") or "").split())
        raw = r.get("commandOutput")
        if isinstance(raw, dict) and any(k in raw for k in _RUNNER_KEYS):
            # The command runner's own shape: {"SUCCESS": {cmd: text}, "FAILURE": {...}, ...}.
            for c, t in (raw.get("SUCCESS") or {}).items():
                entry["output"][c] = _text(c, t)
            for c, t in (raw.get("FAILURE") or {}).items():
                entry.setdefault("failed", {})[c] = redact_config(str(t))
            for c, t in (raw.get("BLACKLISTED") or {}).items():
                entry.setdefault("blocked_by_catalyst_center", {})[c] = redact_config(str(t))
            continue
        if isinstance(raw, dict) and cmd and cmd in raw:
            raw = raw[cmd]
        elif isinstance(raw, dict) and len(raw) == 1:
            raw = next(iter(raw.values()))
        if not cmd:
            continue
        if raw in (None, "", {}, []):
            entry["output"][cmd] = "(no output)"
        else:
            entry["output"][cmd] = _text(cmd, raw)
        if r.get("actionInfo") and isinstance(r["actionInfo"], str):
            entry.setdefault("actions", {})[cmd] = r["actionInfo"]
    return list(merged.values())


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Run an issue's suggested commands", idempotent=False)
    async def catc_run_issue_commands(
        ctx: Context,
        issue_id: Annotated[str, Field(description="Issue id from catc_list_issues")],
    ) -> ToolResult:
        """Run an assurance issue's suggested commands live and return the output per device: Catalyst
        Center's own "Run commands" for the issue's suggested actions (execute-suggested-actions-commands),
        which closes the troubleshooting loop catc_get_issue starts. The issue's commands are checked first
        and the call is refused when any of them is not read-only (show, ping, traceroute or dir), since
        Catalyst Center runs the whole list; nothing runs then. Output is cleaned like
        catc_run_show_commands (echoed command and prompt dropped, secrets masked). An issue with no
        suggested commands returns its actions without running anything. When the execute API refuses the
        issue (some releases only take legacy issue ids), the same checked commands run through the
        command runner on the issue's device instead, and `via` says so."""
        app: CatcApp = get_client(ctx)
        data = await fetch_issue(app, issue_id)
        if not isinstance(data, dict) or not data:
            raise NotFound(f"No assurance issue {issue_id!r}: list them with catc_list_issues.")
        row = issue_row(data)
        issue = {k: row[k] for k in ("id", "name", "summary", "device", "status", "last_seen") if row.get(k)}
        actions = [a for a in suggested_actions(data) if a.get("action") or a.get("commands")]
        allowed, refused = issue_commands(actions)
        if refused:
            raise InvalidRequest(
                f"Refused: issue {issue.get('id') or issue_id} suggests commands that are not read-only "
                f"({', '.join(repr(c) for c in refused)}), and Catalyst Center runs the whole list. Run the "
                "read-only ones yourself with catc_run_show_commands / catc_ping."
            )
        out: dict[str, Any] = {"issue": issue, "suggested_actions": actions}
        if not allowed:
            out["results"] = []
            out["note"] = "This issue has no suggested commands to run: nothing was run."
            return object_result(out, shape=False)
        out["commands"] = allowed
        wait = max(app.settings.mcp_task_timeout, app.settings.command_runner_timeout + 30)
        body = {"entity_type": "issue_id", "entity_value": str(issue.get("id") or issue_id)}
        try:
            started = await app.api.post(EXECUTE_PATH, body)
            job = await app.wait_job(started, ctx=ctx, timeout=wait, what="suggested-action commands")
        except UpstreamError as e:
            # A refusal (400/404/500, a failed execution) falls back; a timeout, login or reachability
            # problem does not: the commands may still be running, or the runner would fail the same way.
            eid = str(data.get("entityId") or "")
            if isinstance(e, NO_FALLBACK) or not (is_device_issue(data) and eid):
                raise
            dev = {"id": eid, "hostname": issue.get("device") or eid}
            results = await run_show(app, ctx, [dev], allowed, name="catc-mcp-issue")
            out["via"] = f"command runner on the issue's device (execute-suggested-actions refused: {e})"
            out["results"] = compact(results, mask_secrets=False)
            return object_result(out, shape=False)
        results = group_results(result_rows(job), issue.get("device"))
        out["via"] = "execute-suggested-actions-commands"
        if job.get("execution_id"):
            out["execution_id"] = job["execution_id"]
        out["results"] = compact(results, mask_secrets=False)
        if not results:
            out["note"] = f"Catalyst Center ran the commands but returned no output: {str(job)[:500]}"
        return object_result(out, shape=False)
