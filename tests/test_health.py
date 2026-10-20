import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_healthcheck_endpoint(async_client: AsyncClient):
    """Verify that /health returns 200 OK and valid status json."""
    response = await async_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == "wilco"
    assert "version" in data
    assert "bot_mode" in data
    assert "bot_configured" in data


@pytest.mark.asyncio
async def test_root_endpoint(async_client: AsyncClient):
    """Verify that / returns 200 OK and service metadata."""
    response = await async_client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["app"] == "wilco"
    assert data["health"] == "/health"

