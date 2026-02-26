"""Shared test fixtures for aumos-legal-overlay."""

import pytest
from httpx import AsyncClient

from aumos_common.testing import UserFactory, override_auth_dependency
from aumos_common.auth import get_current_user

from aumos_legal_overlay.main import app


@pytest.fixture
def mock_user() -> UserFactory:
    """Create a test user with default permissions.

    Returns:
        A UserFactory instance suitable for auth override.
    """
    return UserFactory.create()


@pytest.fixture
async def client(mock_user: UserFactory) -> AsyncClient:
    """Async HTTP client with auth overrides applied.

    Args:
        mock_user: The test user fixture for auth override.

    Returns:
        Configured HTTPX AsyncClient for test requests.
    """
    app.dependency_overrides[get_current_user] = override_auth_dependency(mock_user)
    async with AsyncClient(app=app, base_url="http://test") as async_client:
        yield async_client
    app.dependency_overrides.clear()
