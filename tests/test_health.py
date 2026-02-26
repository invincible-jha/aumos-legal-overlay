"""Basic smoke tests for aumos-legal-overlay.

Verifies the service starts correctly and health endpoints respond
without infrastructure dependencies.
"""

import pytest
from httpx import AsyncClient, ASGITransport

from aumos_legal_overlay.main import app


@pytest.mark.asyncio
async def test_liveness_endpoint_returns_200() -> None:
    """Liveness probe must return 200 OK with no dependencies.

    The /live endpoint must never fail due to infrastructure issues —
    it only signals whether the process itself is alive.
    """
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/live")

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_openapi_schema_is_accessible() -> None:
    """OpenAPI schema endpoint must be accessible in development.

    Verifies the FastAPI app is correctly configured and routes are registered.
    """
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    assert "openapi" in schema
    assert "info" in schema


@pytest.mark.asyncio
async def test_docs_endpoint_is_accessible() -> None:
    """Swagger UI docs endpoint must be accessible.

    Verifies the docs are served correctly for local development.
    """
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/docs")

    assert response.status_code == 200
