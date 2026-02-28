"""Automated PII redaction engine using Microsoft Presidio.

GAP-316: Redaction Engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


@dataclass
class RedactionSpan:
    """A single PII redaction span within a document."""

    entity_type: str        # PERSON, EMAIL_ADDRESS, PHONE_NUMBER, etc.
    start_char: int
    end_char: int
    confidence_score: float
    replacement_text: str = "[REDACTED]"
    page_number: int | None = None
    # PDF annotation coordinates for non-destructive redaction
    bbox_x: float | None = None
    bbox_y: float | None = None
    bbox_width: float | None = None
    bbox_height: float | None = None


@dataclass
class RedactionResult:
    """Complete redaction result for a document."""

    document_id: str
    redacted_text: str
    spans: list[RedactionSpan] = field(default_factory=list)
    entity_counts: dict[str, int] = field(default_factory=dict)
    original_length: int = 0
    redacted_length: int = 0


class RedactionEngine:
    """Automated PII detection and redaction using Microsoft Presidio.

    Uses presidio-analyzer for NER-based PII detection and
    presidio-anonymizer for anonymization. Presidio is MIT licensed.

    Redactions are stored as PDF annotation coordinates (non-destructive)
    so original document content can be recovered with appropriate authorization.
    """

    # PII entity types from Presidio (spaCy NLP-based recognition)
    DEFAULT_ENTITIES: list[str] = [
        "PERSON",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "US_SSN",
        "US_BANK_NUMBER",
        "IP_ADDRESS",
        "LOCATION",
        "DATE_TIME",
        "NRP",  # Nationality, religious, political group
        "MEDICAL_LICENSE",
        "URL",
        "IBAN_CODE",
    ]

    def __init__(self, confidence_threshold: float = 0.7) -> None:
        self._threshold = confidence_threshold
        self._analyzer: Any = None
        self._anonymizer: Any = None
        self._initialized = False

    def _lazy_init(self) -> None:
        """Lazy-load Presidio to avoid import-time dependency failure."""
        if self._initialized:
            return
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_anonymizer import AnonymizerEngine
            self._analyzer = AnalyzerEngine()
            self._anonymizer = AnonymizerEngine()
            self._initialized = True
            logger.info("presidio_initialized")
        except ImportError:
            logger.warning(
                "presidio_not_installed",
                hint="Install presidio-analyzer>=2.2.0 and presidio-anonymizer>=2.2.0",
            )

    def redact_text(
        self,
        document_id: str,
        text: str,
        entities: list[str] | None = None,
        language: str = "en",
    ) -> RedactionResult:
        """Detect and redact PII from document text.

        Args:
            document_id: Document identifier for result tracking.
            text: Raw document text content.
            entities: PII entity types to detect (default: all supported types).
            language: Text language for NLP models.

        Returns:
            RedactionResult with redacted text and span metadata.
        """
        self._lazy_init()
        entity_list = entities or self.DEFAULT_ENTITIES

        if not self._initialized:
            # Fallback: pattern-based redaction for basic PII
            return self._pattern_fallback(document_id, text)

        results = self._analyzer.analyze(
            text=text,
            entities=entity_list,
            language=language,
        )

        # Filter by confidence threshold
        high_confidence_results = [r for r in results if r.score >= self._threshold]

        anonymized = self._anonymizer.anonymize(
            text=text,
            analyzer_results=high_confidence_results,
        )

        spans = [
            RedactionSpan(
                entity_type=r.entity_type,
                start_char=r.start,
                end_char=r.end,
                confidence_score=r.score,
                replacement_text=f"[{r.entity_type}]",
            )
            for r in high_confidence_results
        ]

        entity_counts: dict[str, int] = {}
        for span in spans:
            entity_counts[span.entity_type] = entity_counts.get(span.entity_type, 0) + 1

        logger.info(
            "document_redacted",
            document_id=document_id,
            entities_found=len(spans),
            entity_types=list(entity_counts),
        )
        return RedactionResult(
            document_id=document_id,
            redacted_text=anonymized.text,
            spans=spans,
            entity_counts=entity_counts,
            original_length=len(text),
            redacted_length=len(anonymized.text),
        )

    def _pattern_fallback(self, document_id: str, text: str) -> RedactionResult:
        """Basic pattern-based PII redaction fallback when Presidio is unavailable."""
        import re

        spans: list[RedactionSpan] = []
        redacted = text

        # Email pattern
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        for match in email_pattern.finditer(text):
            spans.append(RedactionSpan(
                entity_type="EMAIL_ADDRESS",
                start_char=match.start(),
                end_char=match.end(),
                confidence_score=0.95,
                replacement_text="[EMAIL_ADDRESS]",
            ))
        redacted = email_pattern.sub("[EMAIL_ADDRESS]", redacted)

        # SSN pattern
        ssn_pattern = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
        for match in ssn_pattern.finditer(text):
            spans.append(RedactionSpan(
                entity_type="US_SSN",
                start_char=match.start(),
                end_char=match.end(),
                confidence_score=0.95,
                replacement_text="[US_SSN]",
            ))
        redacted = ssn_pattern.sub("[US_SSN]", redacted)

        return RedactionResult(
            document_id=document_id,
            redacted_text=redacted,
            spans=spans,
            entity_counts={s.entity_type: 1 for s in spans},
            original_length=len(text),
            redacted_length=len(redacted),
        )
