"""Document processor adapter for aumos-legal-overlay.

Handles document analysis for privilege detection, metadata extraction,
and document format conversion for e-discovery workflows.
"""

import re
from dataclasses import dataclass

from aumos_common.observability import get_logger

logger = get_logger(__name__)


@dataclass
class DocumentAnalysisResult:
    """Result of privilege analysis on a document.

    Attributes:
        document_id: Identifier of the analyzed document.
        detected_privilege_types: Privilege types detected in the document.
        confidence_score: Overall confidence in privilege determination.
        privilege_indicators: Specific indicators found in the document.
        recommended_privilege_basis: Suggested basis for privilege claim.
    """

    document_id: str
    detected_privilege_types: list[str]
    confidence_score: float
    privilege_indicators: list[str]
    recommended_privilege_basis: str | None


# Patterns indicating potential attorney-client privilege
_ATTORNEY_CLIENT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\battorney[-\s]client\b", re.IGNORECASE),
    re.compile(r"\bprivileged\s+and\s+confidential\b", re.IGNORECASE),
    re.compile(r"\blegal\s+advice\b", re.IGNORECASE),
    re.compile(r"\bcounsel\s+opinion\b", re.IGNORECASE),
    re.compile(r"\b(?:esq\.|attorney|counsel)\b", re.IGNORECASE),
]

# Patterns indicating potential work product doctrine
_WORK_PRODUCT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bwork\s+product\b", re.IGNORECASE),
    re.compile(r"\bprepared\s+in\s+anticipation\s+of\s+litigation\b", re.IGNORECASE),
    re.compile(r"\blitigation\s+strategy\b", re.IGNORECASE),
    re.compile(r"\bwitness\s+interview\s+notes?\b", re.IGNORECASE),
    re.compile(r"\binvestigation\s+memo\b", re.IGNORECASE),
]


class DocumentProcessor:
    """Analyzes documents for privilege indicators and metadata extraction.

    Performs pattern-based analysis to identify potential privilege markers,
    providing confidence scores to the PrivilegeService for determination.
    """

    def analyze_for_privilege(self, document_id: str, document_text: str) -> DocumentAnalysisResult:
        """Analyze document text for privilege indicators.

        Scans for known attorney-client privilege and work product
        doctrine markers to produce a confidence score.

        Args:
            document_id: Identifier of the document being analyzed.
            document_text: Raw text content of the document.

        Returns:
            DocumentAnalysisResult with detected privilege types and confidence.
        """
        detected_types: list[str] = []
        indicators: list[str] = []
        match_count = 0
        total_patterns = len(_ATTORNEY_CLIENT_PATTERNS) + len(_WORK_PRODUCT_PATTERNS)

        for pattern in _ATTORNEY_CLIENT_PATTERNS:
            matches = pattern.findall(document_text)
            if matches:
                detected_types.append("attorney_client")
                indicators.extend(matches[:3])  # Cap indicators for brevity
                match_count += 1

        for pattern in _WORK_PRODUCT_PATTERNS:
            matches = pattern.findall(document_text)
            if matches:
                if "work_product" not in detected_types:
                    detected_types.append("work_product")
                indicators.extend(matches[:3])
                match_count += 1

        # Normalize match count to a confidence score
        confidence_score = min(1.0, match_count / max(1, total_patterns * 0.3))

        recommended_basis: str | None = None
        if "attorney_client" in detected_types:
            recommended_basis = (
                "Communication made in confidence for the purpose of obtaining "
                "legal advice from a licensed attorney."
            )
        elif "work_product" in detected_types:
            recommended_basis = (
                "Document prepared in anticipation of litigation by or for a party "
                "or its representative under FRCP 26(b)(3)."
            )

        logger.info(
            "Document privilege analysis complete",
            document_id=document_id,
            detected_types=detected_types,
            confidence_score=round(confidence_score, 3),
            indicator_count=len(indicators),
        )

        return DocumentAnalysisResult(
            document_id=document_id,
            detected_privilege_types=list(set(detected_types)),
            confidence_score=round(confidence_score, 3),
            privilege_indicators=list(set(indicators)),
            recommended_privilege_basis=recommended_basis,
        )

    def extract_metadata(self, document_text: str) -> dict:
        """Extract basic metadata from document text for audit purposes.

        Extracts date references, email addresses, and other metadata
        that may be required for privilege log entries.

        Args:
            document_text: Raw text content of the document.

        Returns:
            Dictionary of extracted metadata fields.
        """
        metadata: dict = {}

        # Extract email addresses (author/recipient candidates)
        email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        emails = list(set(email_pattern.findall(document_text)))
        if emails:
            metadata["email_addresses"] = emails[:20]  # Cap at 20 addresses

        # Extract date references (ISO format)
        date_pattern = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
        dates = list(set(date_pattern.findall(document_text)))
        if dates:
            metadata["date_references"] = sorted(dates)[:10]

        # Detect common legal document types
        doc_type_patterns = {
            "memorandum": re.compile(r"\bmemorandu[m]?\b", re.IGNORECASE),
            "email": re.compile(r"\bfrom:\s*\S+@\S+\b", re.IGNORECASE),
            "contract": re.compile(r"\bagreement\s+between\b", re.IGNORECASE),
            "brief": re.compile(r"\bbrief\s+in\s+(?:support|opposition)\b", re.IGNORECASE),
        }
        for doc_type, pattern in doc_type_patterns.items():
            if pattern.search(document_text):
                metadata["detected_document_type"] = doc_type
                break

        return metadata
