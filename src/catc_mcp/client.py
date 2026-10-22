"""The Catalyst Center "app" object: one ApiClient with token login, a 1-based pager, job polling.

Auth: POST /dna/system/api/v1/auth/token with Basic credentials returns {"Token": "..."}, sent as
X-Auth-Token and valid for about an hour. Intent API lives under /dna/intent/api/v1|v2.

Many writes are asynchronous and return either a task id ({"response": {"taskId": ...}}) or a
business-API execution id ({"executionId": ...}); `wait_job` polls either until it finishes.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
from typing import Any
from urllib.parse import quote

import httpx
from fastmcp import Context

from catc_mcp._core import (
    InvalidRequest,
    NotFound,
    TaskFailed,
    UpstreamError,
    UpstreamTimeout,
    poll_until,
)
from catc_mcp._core.http import (
    ApiClient,
    LoginTokenAuth,
    OffsetLimit,
    RateLimiter,
    StaticHeaderAuth,
    Token,
    basic_header,
)
from catc_mcp._core.secrets import scrub_text
from catc_mcp.config import Settings
from catc_mcp.rbac import BUILTIN_TIERS, account_check, enabled_tier, permissions_tier

log = logging.getLogger(__name__)

PRODUCT = "Catalyst Center"
LOGIN_PATH = "/dna/system/api/v1/auth/token"
TOKEN_LIFETIME = 55 * 60  # tokens last 60 minutes; renew a little early
TASK_PATH = "/dna/intent/api/v1/task/{id}"
EXECUTION_PATH = "/dna/platform/management/business-api/v1/execution-status/{id}"


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def safe_id(value: str, what: str = "id") -> str:
    """An id that is safe to put in a URL path segment (UUIDs and similar); refuses anything else."""
    value = value.strip()
    if not _ID_RE.match(value):
        raise InvalidRequest(f"Invalid {what} {value!r}: expected a UUID-like identifier.")
    return value


def _text(v: Any) -> str | None:
    if isinstance(v, str) and v.strip():
        return v.strip()
    return None


def catc_error_detail(body: Any) -> str | None:
    """Readable message from the many Catalyst Center error shapes:
    {"response": {"errorCode", "message", "detail"}}, {"error": ..., "message": ...},
    {"errorCode", "message", "detail"}, {"bapiError": ...}, [{"message": ...}], or plain text such as
    "Http Error Code:500"."""
    if isinstance(body, str):
        return body.strip()[:500] or None
    if isinstance(body, list):
        items = [d for b in body if (d := catc_error_detail(b))]
        return " | ".join(items)[:500] or None
    if not isinstance(body, dict):
        return None
    inner = body.get("response")
    if isinstance(inner, dict | list) and (d := catc_error_detail(inner)):
        return d
    parts: list[str] = []
    for key in ("errorCode", "error", "message", "detail", "description", "failureReason", "bapiError"):
        v = body.get(key)
        if isinstance(v, dict | list):
            v = catc_error_detail(v)
        if (t := _text(v)) and t not in parts:
            parts.append(t)
    if not parts and isinstance(body.get("errors"), list):
        return catc_error_detail(body["errors"])
    return ": ".join(parts)[:500] or None


class CatcApiClient(ApiClient):
    """ApiClient that keeps Catalyst Center's error body on a 404 too. Core's 404 message names only the
    request, but SD-Access answers 404 with an errorCode and a detail that say what is missing (live
    2026-10-22, #191: NCHS20216 "... has no virtual network with the name INFRA_VN" on POST
    sda/anycastGateways). Other statuses already carry the detail (`error_detail`)."""

    def error_from_response(self, resp: httpx.Response) -> UpstreamError:
        err = super().error_from_response(resp)
        if resp.status_code != 404:
            return err
        try:
            body = resp.json()
        except ValueError:
            return err
        detail = catc_error_detail(body) if isinstance(body, dict | list) else None
        if not detail:
            return err
        return NotFound(
            f"Not found (404): {resp.request.method} {resp.request.url.path}: {scrub_text(detail)}", 404
        )


def job_ref(result: Any) -> tuple[str, str] | None:
    """("task", id) or ("execution", id) if a write response points at an asynchronous job."""
    if not isinstance(result, dict):
        return None
    for d in (result, result.get("response")):
        if not isinstance(d, dict):
            continue
        if isinstance(d.get("taskId"), str):
            return "task", d["taskId"]
        if isinstance(d.get("executionId"), str):
            return "execution", d["executionId"]
    return None


def _task_progress(t: dict[str, Any]) -> str:
    return str(t.get("progress") or t.get("status") or "")


def _task_failed(t: dict[str, Any]) -> str | bool:
    if t.get("isError") or str(t.get("status", "")).upper() == "FAILURE":
        return str(t.get("failureReason") or t.get("progress") or "task reported an error")
    return False


def _exec_failed(e: dict[str, Any]) -> str | bool:
    if str(e.get("status", "")).upper() == "FAILURE":
        err = e.get("bapiError")
        detail = err if isinstance(err, str) else catc_error_detail(err)
        return detail or "execution failed"
    return False


def data_total(body: Any) -> int | None:
    """Total of an Assurance list: `page.count` (data API) or `totalCount` (device-health)."""
    if not isinstance(body, dict):
        return None
    page = body.get("page")
    if isinstance(page, dict) and page.get("count") is not None:
        return int(page["count"])
    total = body.get("totalCount")
    return int(total) if isinstance(total, int | float | str) and str(total).isdigit() else None


class CatcApp:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        limiter = RateLimiter(settings.rate_limit, settings.max_concurrency or 8)
        if settings.token_value():
            auth: Any = StaticHeaderAuth("X-Auth-Token", settings.token_value())
        else:
            auth = LoginTokenAuth(self._login)
        self.api = CatcApiClient(
            settings.url,
            product=PRODUCT,
            env_prefix="CATC_",
            auth=auth,
            verify=settings.verify,
            timeout=settings.timeout,
            retries=settings.retries,
            limiter=limiter,
            headers={"Content-Type": "application/json"},
            error_detail=catc_error_detail,
            transport=transport,
        )
        # One pager per response shape; endpoint-specific page-size caps are passed per call
        # (`max_page=` with the PAGE_* constants in common.py).
        # Intent API lists: {"response": [...]}, 1-based offset, limit <= 500, usually no total.
        self.pager = OffsetLimit(items="response", one_based=True, max_page=500)
        # Assurance lists: like the Intent API but with a total (`page.count` on the data API,
        # `totalCount` on device-health).
        # Defaults are the strictest cap seen on that shape; call sites pass their own `max_page=`.
        self.data_pager = OffsetLimit(items="response", total=data_total, one_based=True, max_page=20)
        # Audit log: a bare JSON list with a 0-based offset and no total.
        self.audit_pager = OffsetLimit(items=None, max_page=25)
        self._version: str | None = None

    async def _login(self, client: ApiClient) -> Token:
        user, password = self.settings.require_credentials("CATC_")  # AuthError if unset
        resp = await client.send_raw(
            "POST", LOGIN_PATH, headers={"Authorization": basic_header(user, password)}
        )
        if resp.status_code != 200:
            raise client.error_from_response(resp)
        try:
            token = resp.json()["Token"]
        except (ValueError, KeyError, TypeError) as e:
            raise UpstreamError(f"{PRODUCT} login returned no Token (HTTP {resp.status_code})") from e
        if not isinstance(token, str) or not token:
            raise UpstreamError(f"{PRODUCT} login returned an empty or malformed Token")
        return Token({"X-Auth-Token": token}, Token.expiring_in(TOKEN_LIFETIME))

    async def aclose(self) -> None:
        await self.api.aclose()

    # --- helpers ---------------------------------------------------------------------------

    async def get_response(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET and unwrap the usual {"response": ...} envelope (bare bodies pass through)."""
        data = await self.api.get(path, params)
        if isinstance(data, dict) and "response" in data:
            return data["response"]
        return data

    async def version(self) -> str:
        if self._version is None:
            rel = await self.get_response("/dna/intent/api/v1/dnac-release")
            rel = rel if isinstance(rel, dict) else {}
            self._version = str(rel.get("installedVersion") or rel.get("displayVersion") or "unknown")
        return self._version

    async def status(self) -> dict[str, Any]:
        version = await self.version()
        out: dict[str, Any] = {
            "product": PRODUCT,
            "version": version,
            "api_user": self.settings.username or "(static token)",
        }
        # Cheap sanity counts; failures here shouldn't hide that login works.
        counts = await asyncio.gather(
            self.get_response("/dna/intent/api/v1/network-device/count"),
            self.get_response("/dna/intent/api/v1/sites/count"),
            return_exceptions=True,
        )
        for key, val in zip(("devices", "sites"), counts, strict=True):
            if isinstance(val, dict):
                val = val.get("count")
            out[key] = val if isinstance(val, int) else f"unavailable ({type(val).__name__})"
        from catc_mcp.tools.sda import sda_application  # tools import the client

        try:
            out["sda"] = await sda_application(self)
        except UpstreamError as e:
            out["sda"] = {"available": "unknown", "reason": str(e)[:200]}
        if self.settings.username:
            try:
                out["account"] = await self.account()
            except UpstreamError as e:
                out["account"] = {"unavailable": str(e)[:200]}
        return out

    async def role_tiers(self) -> dict[str, str] | None:
        """The API account's roles and the server tier each amounts to (rbac.BUILTIN_TIERS for built-in
        roles, rbac.permissions_tier for custom ones; "unknown" when a role can't be read), or None when
        the account is not a local user (external/AAA login). Needs System Administration Read."""
        users = await self.get_response("/dna/system/api/v1/user")
        users = users.get("users", []) if isinstance(users, dict) else []
        me = next(
            (u for u in users if isinstance(u, dict) and u.get("username") == self.settings.username), None
        )
        if me is None:
            return None
        tiers: dict[str, str] = {}
        for role in me.get("roleList") or []:
            role = str(role)
            if role in BUILTIN_TIERS:
                tiers[role] = BUILTIN_TIERS[role]
                continue
            # Custom roles' v2 id is their name (checked on 3.2.2).
            try:
                detail = await self.get_response(f"/dna/system/api/v2/roles/{quote(role, safe='')}")
            except UpstreamError:
                tiers[role] = "unknown"
                continue
            perms = detail.get("permissions", []) if isinstance(detail, dict) else []
            tiers[role] = permissions_tier(perms)
        return tiers

    async def account(self) -> dict[str, Any]:
        """The API account's roles and the server tier they amount to (rbac.account_check)."""
        tiers = await self.role_tiers()
        if tiers is None:
            return {"unavailable": "the account is not a local user (external/AAA login?)"}
        s = self.settings
        return account_check(tiers, enabled_tier(s.mcp_enable_writes, s.mcp_enable_dangerous))

    # --- asynchronous jobs -----------------------------------------------------------------

    async def get_task(self, task_id: str) -> dict[str, Any]:
        t = await self.get_response(TASK_PATH.format(id=safe_id(task_id, "task id")))
        return t if isinstance(t, dict) else {"raw": t}

    async def get_execution(self, execution_id: str) -> dict[str, Any]:
        e = await self.api.get(EXECUTION_PATH.format(id=safe_id(execution_id, "execution id")))
        return e if isinstance(e, dict) else {"raw": e}

    async def run_job(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        ctx: Context | None = None,
        what: str = "task",
        params: dict[str, Any] | None = None,
        timeout: float | None = None,  # noqa: ASYNC109 - overall polling deadline
    ) -> dict[str, Any]:
        """Send a write and wait for the task/execution it starts (if any)."""
        result = await self.api.request(method, path, params=params, json=body)
        return await self.wait_job(result, ctx=ctx, timeout=timeout, what=what)

    async def wait_job(
        self,
        result: Any,
        *,
        ctx: Context | None = None,
        timeout: float | None = None,  # noqa: ASYNC109 - overall polling deadline
        what: str = "task",
    ) -> dict[str, Any]:
        """If `result` names a task or execution, poll it to completion and return a summary
        ({"task_id"|"execution_id", "status", ...}). Otherwise return `result` unchanged (wrapped).
        Raises TaskFailed on failure and UpstreamTimeout (naming catc_get_task) when it runs long."""
        ref = job_ref(result)
        if ref is None:
            return {"result": result}
        kind, job_id = ref
        limit = timeout if timeout is not None else self.settings.mcp_task_timeout
        try:
            if kind == "task":
                t = await poll_until(
                    lambda: self.get_task(job_id),
                    done=lambda t: t.get("endTime") is not None,
                    failed=_task_failed,
                    describe=_task_progress,
                    timeout=limit,
                    ctx=ctx,
                    what=what,
                    interval=1.0,
                )
                return {"task_id": job_id, "status": "SUCCESS", **task_summary(t)}
            e = await poll_until(
                lambda: self.get_execution(job_id),
                done=lambda e: str(e.get("status", "")).upper() in ("SUCCESS", "FAILURE"),
                failed=_exec_failed,
                describe=lambda e: str(e.get("status", "")),
                timeout=limit,
                ctx=ctx,
                what=what,
                interval=1.0,
            )
            return {"execution_id": job_id, "status": e.get("status"), **exec_summary(e)}
        except TaskFailed as err:
            raise TaskFailed(f"{err} ({kind} id {job_id}; inspect with catc_get_task)") from err
        except UpstreamTimeout as err:
            raise UpstreamTimeout(f"{err} Check it with catc_get_task(task_id='{job_id}').") from err


def task_summary(t: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ("progress", "data", "resultLocation", "startTime", "endTime"):
        if t.get(key) not in (None, ""):
            out[key] = t[key]
    prog = out.get("progress")
    if isinstance(prog, str) and prog.startswith("{"):
        with contextlib.suppress(ValueError):
            out["progress"] = json.loads(prog)
    return out


def exec_summary(e: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ("bapiName", "bapiSyncResponse", "bapiError", "startTime", "endTime"):
        if e.get(key) not in (None, ""):
            out[key] = e[key]
    sync = out.get("bapiSyncResponse")
    if isinstance(sync, str) and sync.startswith(("{", "[")):
        with contextlib.suppress(ValueError):
            out["bapiSyncResponse"] = json.loads(sync)
    return out
