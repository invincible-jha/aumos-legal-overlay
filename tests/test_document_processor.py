"""Unit tests for DocumentProcessor adapter.

Tests privilege pattern detection and metadata extraction
without any infrastructure dependencies.
"""

import pytest

from aumos_legal_overlay.adapters.document_processor import DocumentProcessor


@pytest.fixture
def processor() -> DocumentProcessor:
    """Provide a DocumentProcessor instance for testing.

    Returns:
        Configured DocumentProcessor.
    """
    return DocumentProcessor()


class TestPrivilegeAnalysis:
    """Tests for DocumentProcessor.analyze_for_privilege."""

    def test_detects_attorney_client_privilege_pattern(
        self, processor: DocumentProcessor
    ) -> None:
        """Strong attorney-client markers must yield high confidence scores."""
        document_text = (
            "PRIVILEGED AND CONFIDENTIAL\n"
            "ATTORNEY-CLIENT COMMUNICATION\n"
            "Dear Counsel,\n"
            "Please provide legal advice on this matter. The attorney client relationship "
            "between our firm and your practice requires..."
        )

        result = processor.analyze_for_privilege("doc-001", document_text)

        assert "attorney_client" in result.detected_privilege_types
        assert result.confidence_score > 0.0
        assert result.recommended_privilege_basis is not None

    def test_detects_work_product_privilege_pattern(
        self, processor: DocumentProcessor
    ) -> None:
        """Work product markers must be detected correctly."""
        document_text = (
            "WORK PRODUCT — DO NOT DISCLOSE\n"
            "Prepared in anticipation of litigation.\n"
            "Litigation strategy memo regarding the upcoming trial."
        )

        result = processor.analyze_for_privilege("doc-002", document_text)

        assert "work_product" in result.detected_privilege_types
        assert result.confidence_score > 0.0

    def test_no_privilege_markers_yields_zero_confidence(
        self, processor: DocumentProcessor
    ) -> None:
        """Documents with no privilege markers must have zero confidence."""
        document_text = "Invoice #12345. Amount due: $5,000. Payment terms: net 30."

        result = processor.analyze_for_privilege("doc-003", document_text)

        assert result.confidence_score == 0.0
        assert result.detected_privilege_types == []
        assert result.recommended_privilege_basis is None

    def test_analysis_result_contains_document_id(
        self, processor: DocumentProcessor
    ) -> None:
        """Analysis result must reference the provided document ID."""
        result = processor.analyze_for_privilege("my-doc-id", "some text")

        assert result.document_id == "my-doc-id"

    def test_confidence_score_capped_at_one(
        self, processor: DocumentProcessor
    ) -> None:
        """Confidence score must never exceed 1.0."""
        heavily_privileged_text = " ".join(
            [
                "attorney-client",
                "privileged and confidential",
                "legal advice",
                "counsel opinion",
                "Esq.",
                "work product",
                "prepared in anticipation of litigation",
                "litigation strategy",
                "witness interview notes",
                "investigation memo",
            ]
            * 5
        )

        result = processor.analyze_for_privilege("doc-004", heavily_privileged_text)

        assert result.confidence_score <= 1.0


class TestMetadataExtraction:
    """Tests for DocumentProcessor.extract_metadata."""

    def test_extracts_email_addresses(self, processor: DocumentProcessor) -> None:
        """Email addresses in document text must be extracted."""
        document_text = "From: alice@example.com\nTo: bob@lawfirm.com\nCC: charlie@corp.com"

        metadata = processor.extract_metadata(document_text)

        assert "email_addresses" in metadata
        assert "alice@example.com" in metadata["email_addresses"]
        assert "bob@lawfirm.com" in metadata["email_addresses"]

    def test_extracts_iso_date_references(self, processor: DocumentProcessor) -> None:
        """ISO date strings in document text must be extracted."""
        document_text = "This agreement dated 2024-01-15 supersedes the 2023-06-30 version."

        metadata = processor.extract_metadata(document_text)

        assert "date_references" in metadata
        assert "2024-01-15" in metadata["date_references"]
        assert "2023-06-30" in metadata["date_references"]

    def test_detects_email_document_type(self, processor: DocumentProcessor) -> None:
        """Documents with email headers must be identified as email type."""
        document_text = "From: alice@example.com\nSubject: Re: Contract review"

        metadata = processor.extract_metadata(document_text)

        assert metadata.get("detected_document_type") == "email"

    def test_empty_document_returns_empty_metadata(
        self, processor: DocumentProcessor
    ) -> None:
        """Empty document text must return empty metadata dict."""
        metadata = processor.extract_metadata("")

        assert metadata == {}
