"""Document Management System integration adapters (iManage, NetDocuments).

GAP-317: DMS Integration.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

import httpx

from aumos_common.observability import get_logger

logger = get_logger(__name__)


@runtime_checkable
class IDMSAdapter(Protocol):
    """Protocol for Document Management System adapters.

    Implementations provide get_document(), list_documents(), and apply_hold().
    Factory selects concrete implementation based on AUMOS_LEGAL_DMS_PROVIDER env var.
    """

    async def get_document(self, document_id: str) -> dict[str, Any]:
        """Retrieve document metadata from the DMS.

        Args:
            document_id: DMS-specific document identifier.

        Returns:
            Document metadata dict.
        """
        ...

    async def list_documents(
        self,
        workspace_id: str,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        """List documents in a workspace.

        Args:
            workspace_id: DMS workspace/matter/folder identifier.
            page: Page number (1-based).
            page_size: Documents per page.

        Returns:
            List of document metadata dicts.
        """
        ...

    async def apply_hold(self, document_id: str, hold_id: str, reason: str) -> bool:
        """Apply a legal hold to a document in the DMS.

        Args:
            document_id: DMS document identifier.
            hold_id: Legal hold UUID from lgl_legal_holds.
            reason: Hold reason for audit trail.

        Returns:
            True if hold applied successfully.
        """
        ...


class IManageAdapter:
    """iManage Work 10 REST API adapter.

    Connects to iManage Work 10 using REST API v1. iManage is the
    most widely deployed DMS in AmLaw 200 law firms.

    Authentication: OAuth 2.0 client credentials with iManage IMS.
    """

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        http_client: httpx.AsyncClient,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._client = http_client
        self._access_token: str | None = None

    async def _authenticate(self) -> str:
        """Authenticate with iManage IMS and return access token."""
        response = await self._client.post(
            f"{self._base_url}/auth/oauth2/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": "user",
            },
            timeout=30.0,
        )
        response.raise_for_status()
        token = response.json()["access_token"]
        self._access_token = token
        return token

    def _auth_headers(self) -> dict[str, str]:
        """Return auth headers for iManage API calls."""
        return {"X-Auth-Token": self._access_token or ""}

    async def get_document(self, document_id: str) -> dict[str, Any]:
        """Retrieve document metadata from iManage Work 10.

        Args:
            document_id: iManage document ID (e.g. "ACTIVE!1234.1").

        Returns:
            Document metadata dict with name, author, date, workspace.
        """
        if not self._access_token:
            await self._authenticate()
        response = await self._client.get(
            f"{self._base_url}/work/api/v1/documents/{document_id}",
            headers=self._auth_headers(),
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json().get("data", {})

    async def list_documents(
        self,
        workspace_id: str,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        """List documents in an iManage workspace/matter."""
        if not self._access_token:
            await self._authenticate()
        response = await self._client.get(
            f"{self._base_url}/work/api/v1/workspaces/{workspace_id}/documents",
            headers=self._auth_headers(),
            params={"page_num": page, "page_size": page_size},
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json().get("data", {}).get("results", [])

    async def apply_hold(self, document_id: str, hold_id: str, reason: str) -> bool:
        """Apply a legal hold by setting document retention properties."""
        if not self._access_token:
            await self._authenticate()
        try:
            response = await self._client.patch(
                f"{self._base_url}/work/api/v1/documents/{document_id}",
                headers=self._auth_headers(),
                json={
                    "data": {
                        "custom_fields": {
                            "legal_hold_id": hold_id,
                            "legal_hold_reason": reason,
                            "is_on_hold": True,
                        }
                    }
                },
                timeout=30.0,
            )
            response.raise_for_status()
            logger.info("imanage_hold_applied", document_id=document_id, hold_id=hold_id)
            return True
        except httpx.HTTPError as exc:
            logger.error("imanage_hold_failed", document_id=document_id, error=str(exc))
            return False


class NetDocumentsAdapter:
    """NetDocuments REST API adapter.

    NetDocuments is a cloud-native DMS popular with mid-size law firms.
    Uses OAuth 2.0 authorization code flow with refresh tokens.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        http_client: httpx.AsyncClient,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._client = http_client

    def _auth_headers(self) -> dict[str, str]:
        """Return auth headers for NetDocuments API calls."""
        return {"Authorization": f"Bearer {self._api_key}"}

    async def get_document(self, document_id: str) -> dict[str, Any]:
        """Retrieve document metadata from NetDocuments."""
        response = await self._client.get(
            f"{self._base_url}/v1/Document/{document_id}",
            headers=self._auth_headers(),
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json()

    async def list_documents(
        self,
        workspace_id: str,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        """List documents in a NetDocuments cabinet/folder."""
        response = await self._client.get(
            f"{self._base_url}/v1/Cabinet/{workspace_id}/Documents",
            headers=self._auth_headers(),
            params={"page": page, "pageSize": page_size},
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json().get("results", [])

    async def apply_hold(self, document_id: str, hold_id: str, reason: str) -> bool:
        """Apply a legal hold via NetDocuments document lock."""
        try:
            response = await self._client.put(
                f"{self._base_url}/v1/Document/{document_id}/attributes",
                headers=self._auth_headers(),
                json={"legalHoldId": hold_id, "legalHoldReason": reason},
                timeout=30.0,
            )
            response.raise_for_status()
            logger.info("netdocuments_hold_applied", document_id=document_id, hold_id=hold_id)
            return True
        except httpx.HTTPError as exc:
            logger.error("netdocuments_hold_failed", document_id=document_id, error=str(exc))
            return False


def get_dms_adapter(
    provider: str,
    config: dict[str, Any],
    http_client: httpx.AsyncClient,
) -> IDMSAdapter:
    """Factory function selecting DMS adapter based on AUMOS_LEGAL_DMS_PROVIDER.

    Args:
        provider: DMS provider key: "imanage" or "netdocuments".
        config: Provider-specific configuration dict.
        http_client: Shared async HTTP client.

    Returns:
        Concrete IDMSAdapter implementation.

    Raises:
        ValueError: If provider is not supported.
    """
    if provider == "imanage":
        return IManageAdapter(
            base_url=config["base_url"],
            client_id=config["client_id"],
            client_secret=config["client_secret"],
            http_client=http_client,
        )
    if provider == "netdocuments":
        return NetDocumentsAdapter(
            base_url=config["base_url"],
            api_key=config["api_key"],
            http_client=http_client,
        )
    raise ValueError(f"Unsupported DMS provider: {provider}. Use: imanage, netdocuments")
