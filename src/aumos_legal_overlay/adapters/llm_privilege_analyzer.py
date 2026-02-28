"""LLM-powered attorney-client privilege analyzer via aumos-llm-serving.

GAP-312: ML-Based Privilege Analysis.
"""
from __future__ import annotations

import json
from enum import Enum
from typing import TYPE_CHECKING, Literal

import httpx
from pydantic import BaseModel, Field

from aumos_common.observability import get_logger

if TYPE_CHECKING:
    from aumos_legal_overlay.adapters.document_processor import DocumentProcessor

logger = get_logger(__name__)

PRIVILEGE_CLASSIFICATION_PROMPT = """You are a legal privilege classifier for e-discovery.
Analyze the following document and classify its privilege status under US law.

Document metadata:
{metadata_json}

Document excerpt (first 2000 characters):
{document_excerpt}

Respond ONLY with valid JSON in this exact format:
{{
  "is_privileged": true|false,
  "privilege_type": "attorney_client"|"work_product"|"common_interest"|"mediation"|"not_privileged",
  "confidence_score": 0.0-1.0,
  "reasoning": "one sentence explanation"
}}

Legal standards to apply:
- Attorney-client privilege: communication between attorney and client for legal advice
- Work product doctrine: materials prepared in anticipation of litigation
- Common interest: shared privilege between co-defendants or co-plaintiffs
- Mediation privilege: communications in mediation proceedings
"""


class PrivilegeType(str, Enum):
    """Attorney-client privilege type classifications."""

    ATTORNEY_CLIENT = "attorney_client"
    WORK_PRODUCT = "work_product"
    COMMON_INTEREST = "common_interest"
    MEDIATION = "mediation"
    NOT_PRIVILEGED = "not_privileged"


class PrivilegeAnalysisResult(BaseModel):
    """Result of LLM-based privilege analysis.

    analysis_method is always recorded for audit transparency —
    mis-classified privileged documents waive privilege irreversibly.
    """

    is_privileged: bool
    privilege_type: PrivilegeType
    confidence_score: float = Field(ge=0.0, le=1.0)
    reasoning: str
    analysis_method: Literal["llm", "pattern_fallback"] = "llm"
    llm_model_id: str = ""


class LLMPrivilegeAnalyzer:
    """Privilege classifier using aumos-llm-serving structured outputs.

    Falls back to pattern-based analysis if LLM service is unavailable.
    Temperature is always 0.0 for deterministic legal classification —
    the same document must always produce the same privilege determination.

    Architecture decisions:
    - response_format: json_object ensures parseable results. Free-text LLM
      responses cannot be reliably parsed for legal privilege determinations.
    - Fallback to pattern analysis (not failure) — legal hold workflows
      cannot block on external service availability.
    """

    def __init__(
        self,
        llm_serving_url: str,
        llm_model_id: str,
        http_client: httpx.AsyncClient,
        fallback_analyzer: "DocumentProcessor",
        confidence_threshold: float = 0.85,
    ) -> None:
        self._llm_url = llm_serving_url
        self._model_id = llm_model_id
        self._client = http_client
        self._fallback = fallback_analyzer
        self._threshold = confidence_threshold

    async def analyze(
        self,
        document_id: str,
        document_metadata: dict,
        document_excerpt: str,
    ) -> PrivilegeAnalysisResult:
        """Analyze document privilege using LLM with pattern fallback.

        Args:
            document_id: Document UUID for audit correlation.
            document_metadata: Dict with type, from, to, date fields.
            document_excerpt: First 2000 characters of document content.

        Returns:
            PrivilegeAnalysisResult with privilege determination and confidence.
        """
        try:
            return await self._llm_analyze(document_metadata, document_excerpt)
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            logger.warning(
                "llm_privilege_fallback",
                document_id=document_id,
                reason=str(exc),
            )
            return await self._pattern_fallback(document_metadata, document_excerpt)

    async def _llm_analyze(self, metadata: dict, excerpt: str) -> PrivilegeAnalysisResult:
        """Call aumos-llm-serving for privilege classification."""
        prompt = PRIVILEGE_CLASSIFICATION_PROMPT.format(
            metadata_json=json.dumps(metadata, indent=2),
            document_excerpt=excerpt[:2000],
        )
        response = await self._client.post(
            f"{self._llm_url}/api/v1/llm/complete",
            json={
                "model_id": self._model_id,
                "prompt": prompt,
                "max_tokens": 300,
                "response_format": {"type": "json_object"},
                "temperature": 0.0,  # Deterministic for legal classification
            },
            timeout=30.0,
        )
        response.raise_for_status()
        parsed = json.loads(response.json()["choices"][0]["text"])
        return PrivilegeAnalysisResult(
            is_privileged=parsed["is_privileged"],
            privilege_type=PrivilegeType(parsed["privilege_type"]),
            confidence_score=float(parsed["confidence_score"]),
            reasoning=parsed["reasoning"],
            analysis_method="llm",
            llm_model_id=self._model_id,
        )

    async def _pattern_fallback(self, metadata: dict, excerpt: str) -> PrivilegeAnalysisResult:
        """Fall back to pattern-based scoring when LLM is unavailable."""
        score = self._fallback.score_document(excerpt, metadata)
        return PrivilegeAnalysisResult(
            is_privileged=score >= self._threshold,
            privilege_type=(
                PrivilegeType.ATTORNEY_CLIENT
                if score >= self._threshold
                else PrivilegeType.NOT_PRIVILEGED
            ),
            confidence_score=score,
            reasoning="Pattern-based scoring (LLM service unavailable)",
            analysis_method="pattern_fallback",
        )
