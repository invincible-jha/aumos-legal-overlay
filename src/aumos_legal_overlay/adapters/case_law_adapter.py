"""Case law database integration via CourtListener free API.

GAP-314: Case Law Database Integration.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# CourtListener API base (PACER data, federal opinions, RECAP archive)
COURTLISTENER_BASE_URL = "https://www.courtlistener.com/api/rest/v4"

# Federal court jurisdiction identifiers
FEDERAL_JURISDICTIONS: dict[str, str] = {
    "SCOTUS": "scotus",
    "CA1": "ca1",    # First Circuit
    "CA2": "ca2",    # Second Circuit
    "CA3": "ca3",    # Third Circuit
    "CA4": "ca4",    # Fourth Circuit
    "CA5": "ca5",    # Fifth Circuit
    "CA6": "ca6",    # Sixth Circuit
    "CA7": "ca7",    # Seventh Circuit
    "CA8": "ca8",    # Eighth Circuit
    "CA9": "ca9",    # Ninth Circuit
    "CA10": "ca10",  # Tenth Circuit
    "CA11": "ca11",  # Eleventh Circuit
    "CADC": "cadc",  # DC Circuit
}


@dataclass
class CaseCitation:
    """Legal case citation record."""

    case_id: str
    case_name: str
    citation: str
    court: str
    jurisdiction: str
    decision_date: str | None
    docket_number: str | None
    summary: str = ""
    url: str = ""
    source: str = "courtlistener"
    retrieved_at: datetime = field(default_factory=datetime.utcnow)


class CaseLawAdapter:
    """Integrates with CourtListener for case law research.

    CourtListener provides free access to PACER data, federal court opinions,
    and the RECAP archive. Enterprise deployments can optionally configure
    Westlaw or LexisNexis for richer coverage.

    Rate limits: CourtListener enforces 50 requests/minute for unauthenticated
    access. Authenticated API tokens increase this to 5000 requests/day.
    """

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        api_token: str | None = None,
        westlaw_api_key: str | None = None,
    ) -> None:
        self._client = http_client
        self._api_token = api_token
        self._westlaw_api_key = westlaw_api_key

    def _auth_headers(self) -> dict[str, str]:
        """Return CourtListener auth headers if token configured."""
        headers: dict[str, str] = {"Accept": "application/json"}
        if self._api_token:
            headers["Authorization"] = f"Token {self._api_token}"
        return headers

    async def search_cases(
        self,
        query: str,
        jurisdiction: str | None = None,
        date_after: str | None = None,
        date_before: str | None = None,
        page_size: int = 20,
    ) -> list[CaseCitation]:
        """Search federal case law by keyword query.

        Args:
            query: Search query (keywords, case name, or citation).
            jurisdiction: Optional court jurisdiction filter (SCOTUS, CA9, etc.).
            date_after: Filter decisions after this date (YYYY-MM-DD).
            date_before: Filter decisions before this date (YYYY-MM-DD).
            page_size: Max results per request.

        Returns:
            List of CaseCitation records matching the query.
        """
        params: dict[str, Any] = {
            "q": query,
            "type": "o",  # opinions
            "order_by": "score desc",
            "stat_Precedential": "on",
            "format": "json",
        }

        if jurisdiction:
            court_id = FEDERAL_JURISDICTIONS.get(jurisdiction, jurisdiction.lower())
            params["court"] = court_id
        if date_after:
            params["filed_after"] = date_after
        if date_before:
            params["filed_before"] = date_before

        try:
            response = await self._client.get(
                f"{COURTLISTENER_BASE_URL}/search/",
                params=params,
                headers=self._auth_headers(),
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()

            citations: list[CaseCitation] = []
            for result in data.get("results", [])[:page_size]:
                citations.append(
                    CaseCitation(
                        case_id=str(result.get("id", "")),
                        case_name=result.get("caseName", ""),
                        citation=result.get("citation", [""])[0] if result.get("citation") else "",
                        court=result.get("court", ""),
                        jurisdiction=jurisdiction or "federal",
                        decision_date=result.get("dateFiled"),
                        docket_number=result.get("docketNumber"),
                        summary=result.get("snippet", "")[:500],
                        url=f"https://www.courtlistener.com{result.get('absolute_url', '')}",
                    )
                )
            logger.info("case_law_search", query=query, results=len(citations))
            return citations

        except httpx.HTTPError as exc:
            logger.error("case_law_search_failed", query=query, error=str(exc))
            return []

    async def get_case(self, case_id: str) -> CaseCitation | None:
        """Retrieve a specific case by CourtListener ID.

        Args:
            case_id: CourtListener opinion ID.

        Returns:
            CaseCitation or None if not found.
        """
        try:
            response = await self._client.get(
                f"{COURTLISTENER_BASE_URL}/opinions/{case_id}/",
                headers=self._auth_headers(),
                timeout=30.0,
            )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            data = response.json()
            return CaseCitation(
                case_id=case_id,
                case_name=data.get("case_name", ""),
                citation=data.get("citation", ""),
                court=data.get("court_id", ""),
                jurisdiction="federal",
                decision_date=data.get("date_filed"),
                docket_number=data.get("docket_id"),
                url=f"https://www.courtlistener.com/opinion/{case_id}/",
            )
        except httpx.HTTPError as exc:
            logger.error("case_law_get_failed", case_id=case_id, error=str(exc))
            return None
