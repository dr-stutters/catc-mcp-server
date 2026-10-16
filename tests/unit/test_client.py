import httpx
import pytest
import respx

from catc_mcp._core import AuthError, TaskFailed, UpstreamTimeout, ValidationFailed
from catc_mcp.client import CatcApp, catc_error_detail, job_ref

from .conftest import make_settings


def test_error_detail_shapes() -> None:
    assert catc_error_detail("Http Error Code:500") == "Http Error Code:500"
    assert (
        catc_error_detail({"response": {"errorCode": "NCTP1", "message": "Bad", "detail": "name exists"}})
        == "NCTP1: Bad: name exists"
    )
    assert catc_error_detail({"error": "invalid", "message": "Invalid site"}) == "invalid: Invalid site"
    assert catc_error_detail([{"message": "a"}, {"message": "b"}]) == "a | b"
    assert catc_error_detail({"bapiError": "boom", "status": "FAILURE"}) == "boom"
    assert catc_error_detail({}) is None


def test_job_ref() -> None:
    assert job_ref({"response": {"taskId": "t1", "url": "/x"}}) == ("task", "t1")
    assert job_ref({"executionId": "e1", "executionStatusUrl": "/y"}) == ("execution", "e1")
    assert job_ref({"response": []}) is None
    assert job_ref(None) is None


async def test_login_sends_basic_and_uses_token(api: respx.MockRouter) -> None:
    route = api.get("/dna/intent/api/v1/sites").respond(json={"response": []})
    app = CatcApp(make_settings())
    try:
        assert await app.get_response("/dna/intent/api/v1/sites") == []
    finally:
        await app.aclose()
    login = api.routes[0].calls.last.request
    assert login.headers["Authorization"].startswith("Basic ")
    assert route.calls.last.request.headers["X-Auth-Token"] == "tok-123"


async def test_login_failure_is_auth_error() -> None:
    with respx.mock(base_url="https://catc.test") as r:
        r.post("/dna/system/api/v1/auth/token").respond(401, json={"error": "Authentication has failed"})
        app = CatcApp(make_settings())
        with pytest.raises(AuthError, match="CATC_USERNAME"):
            await app.get_response("/dna/intent/api/v1/sites")
        await app.aclose()


async def test_relogin_on_401(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/tag").mock(
        side_effect=[httpx.Response(401, json={}), httpx.Response(200, json={"response": [{"name": "x"}]})]
    )
    app = CatcApp(make_settings())
    assert await app.get_response("/dna/intent/api/v1/tag") == [{"name": "x"}]
    assert api.routes[0].call_count == 2
    await app.aclose()


async def test_static_token(api: respx.MockRouter) -> None:
    route = api.get("/dna/intent/api/v1/tag").respond(json={"response": []})
    app = CatcApp(make_settings(token="abc"))
    await app.get_response("/dna/intent/api/v1/tag")
    assert route.calls.last.request.headers["X-Auth-Token"] == "abc"
    assert api.routes[0].call_count == 0
    await app.aclose()


async def test_validation_error_uses_extractor(api: respx.MockRouter) -> None:
    api.post("/dna/intent/api/v1/tag").respond(
        400, json={"response": {"errorCode": "BadRequest", "message": "Tag exists"}}
    )
    app = CatcApp(make_settings())
    with pytest.raises(ValidationFailed, match="Tag exists"):
        await app.api.post("/dna/intent/api/v1/tag", {"name": "x"})
    await app.aclose()


async def test_paging_is_one_based(api: respx.MockRouter) -> None:
    route = api.get("/dna/intent/api/v1/network-device").respond(json={"response": [{"id": "a"}]})
    app = CatcApp(make_settings())
    page = await app.pager.fetch_page(app.api, "/dna/intent/api/v1/network-device", limit=10, offset=0)
    assert route.calls.last.request.url.params["offset"] == "1"
    assert page.items == [{"id": "a"}] and page.complete
    await app.aclose()


async def test_wait_task_success_and_failure(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/task/t1").mock(
        side_effect=[
            httpx.Response(200, json={"response": {"progress": "running"}}),
            httpx.Response(200, json={"response": {"progress": "done", "endTime": 2, "data": "x"}}),
        ]
    )
    api.get("/dna/intent/api/v1/task/t2").respond(
        json={"response": {"isError": True, "failureReason": "bad things", "endTime": 1}}
    )
    app = CatcApp(make_settings())
    out = await app.wait_job({"response": {"taskId": "t1"}})
    assert out["status"] == "SUCCESS" and out["data"] == "x"
    with pytest.raises(TaskFailed, match="bad things"):
        await app.wait_job({"response": {"taskId": "t2"}})
    await app.aclose()


async def test_wait_execution_and_timeout(api: respx.MockRouter) -> None:
    api.get("/dna/platform/management/business-api/v1/execution-status/e1").respond(
        json={"status": "SUCCESS", "bapiSyncResponse": '{"id": "s1"}'}
    )
    api.get("/dna/intent/api/v1/task/slow").respond(json={"response": {"progress": "still"}})
    app = CatcApp(make_settings())
    out = await app.wait_job({"executionId": "e1"})
    assert out["bapiSyncResponse"] == {"id": "s1"}
    with pytest.raises(UpstreamTimeout, match="catc_get_task"):
        await app.wait_job({"response": {"taskId": "slow"}}, timeout=0.01)
    await app.aclose()


async def test_bad_ids_refused(api: respx.MockRouter) -> None:
    from catc_mcp._core import InvalidRequest

    app = CatcApp(make_settings())
    with pytest.raises(InvalidRequest):
        await app.get_task("../../network-device")
    await app.aclose()


async def test_get_task_auto_falls_back_to_execution(api: respx.MockRouter) -> None:
    from catc_mcp._core.testing import call_tool
    from catc_mcp.server import create_server

    api.get("/dna/intent/api/v1/task/e9").respond(404, json={"response": {"errorCode": "INVALID_TASK"}})
    api.get("/dna/platform/management/business-api/v1/execution-status/e9").respond(
        json={"status": "SUCCESS"}
    )
    out = await call_tool(create_server(make_settings()), "catc_get_task", {"task_id": "e9"})
    assert out["execution_id"] == "e9" and out["status"] == "SUCCESS"


async def test_missing_credentials_is_auth_error() -> None:
    app = CatcApp(make_settings(username=None, password=None))
    with pytest.raises(AuthError, match="CATC_USERNAME"):
        await app._login(app.api)
    await app.aclose()
