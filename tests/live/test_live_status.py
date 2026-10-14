import pytest
from fastmcp import Client

pytestmark = pytest.mark.live


async def test_status(lab: Client) -> None:  # type: ignore[type-arg]
    res = await lab.call_tool("catc_status", {})
    data = res.structured_content
    assert data is not None
    assert data["catc"]["version"].startswith("3.")
    assert isinstance(data["catc"]["devices"], int)
    assert isinstance(data["catc"]["sites"], int)
