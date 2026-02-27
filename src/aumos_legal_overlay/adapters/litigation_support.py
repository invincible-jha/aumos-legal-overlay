"""Litigation support adapter for aumos-legal-overlay.

Handles e-discovery workflows including document collection, privilege review,
Bates numbering, production formatting, and Technology Assisted Review (TAR).
"""

import hashlib
import random
import string
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


# Document types eligible for e-discovery production
_EDISCOVERY_DOCUMENT_TYPES: list[str] = [
    "email", "memo", "contract", "spreadsheet", "presentation",
    "instant_message", "text_message", "voicemail_transcript",
    "calendar_entry", "database_record", "log_file",
]

# TAR confidence tiers
_TAR_CONFIDENCE_TIERS: dict[str, dict[str, Any]] = {
    "highly_responsive": {"probability_range": (0.85, 1.0), "action": "produce"},
    "likely_responsive": {"probability_range": (0.65, 0.85), "action": "attorney_review"},
    "uncertain": {"probability_range": (0.40, 0.65), "action": "secondary_review"},
    "likely_non_responsive": {"probability_range": (0.20, 0.40), "action": "spot_check"},
    "non_responsive": {"probability_range": (0.0, 0.20), "action": "withhold"},
}

# Production format specifications
_PRODUCTION_FORMATS: dict[str, dict[str, Any]] = {
    "concordance": {
        "description": "Concordance DAT/OPT format for litigation databases",
        "file_extension": ".dat",
        "delimiter": "|",
        "includes_metadata": True,
        "includes_images": True,
    },
    "summation": {
        "description": "Summation DII format",
        "file_extension": ".dii",
        "delimiter": ",",
        "includes_metadata": True,
        "includes_images": True,
    },
    "native": {
        "description": "Native file format preservation",
        "file_extension": None,
        "delimiter": None,
        "includes_metadata": False,
        "includes_images": False,
    },
    "pdf": {
        "description": "Searchable PDF production",
        "file_extension": ".pdf",
        "delimiter": None,
        "includes_metadata": True,
        "includes_images": True,
    },
}

# Privilege tags for review
_PRIVILEGE_TAGS: list[str] = [
    "attorney_client_privilege",
    "work_product",
    "joint_defense",
    "common_interest",
    "mediation_privilege",
    "settlement_privilege",
]


@dataclass
class DocumentRecord:
    """An e-discovery document record.

    Attributes:
        document_id: Internal document identifier.
        bates_number: Assigned Bates number for production.
        custodian: Custodian who possessed the document.
        document_type: Type of document (email, memo, etc.).
        document_date: Date of the document.
        subject: Document subject or title.
        file_hash: SHA-256 hash for integrity tracking.
        is_privileged: Whether document is withheld on privilege grounds.
        privilege_tags: Applied privilege designations.
        is_responsive: Whether document is responsive to discovery requests.
        is_redacted: Whether document has been redacted.
        tar_confidence: TAR responsiveness confidence score.
        tar_tier: TAR confidence tier classification.
        production_status: Current production status.
        metadata: Additional document metadata.
    """

    document_id: str
    bates_number: str
    custodian: str
    document_type: str
    document_date: datetime
    subject: str
    file_hash: str
    is_privileged: bool
    privilege_tags: list[str]
    is_responsive: bool
    is_redacted: bool
    tar_confidence: float
    tar_tier: str
    production_status: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProductionPackage:
    """A production package for document delivery to opposing counsel.

    Attributes:
        production_id: Unique production identifier.
        case_number: Associated case number.
        production_date: Date of production.
        bates_range_start: Starting Bates number.
        bates_range_end: Ending Bates number.
        document_count: Total documents produced.
        format: Production format used.
        privilege_log_included: Whether a privilege log is included.
        total_pages: Estimated total page count.
        production_log: Detailed log of produced documents.
        integrity_hash: SHA-256 of the production manifest.
    """

    production_id: str
    case_number: str
    production_date: datetime
    bates_range_start: str
    bates_range_end: str
    document_count: int
    format: str
    privilege_log_included: bool
    total_pages: int
    production_log: list[dict[str, str]]
    integrity_hash: str


class LitigationSupport:
    """Manages e-discovery workflows for litigation readiness.

    Handles document collection, Bates numbering, TAR classification,
    privilege review tagging, production formatting, and production log
    tracking for legal discovery obligations.
    """

    def __init__(
        self,
        case_number: str,
        bates_prefix: str = "PROD",
        starting_bates_sequence: int = 1,
    ) -> None:
        """Initialize the litigation support handler for a case.

        Args:
            case_number: Official case number for this discovery matter.
            bates_prefix: Bates number prefix (e.g., "ACME", "PROD").
            starting_bates_sequence: Starting sequence number for Bates.
        """
        self._case_number = case_number
        self._bates_prefix = bates_prefix
        self._bates_counter = starting_bates_sequence
        self._document_registry: dict[str, DocumentRecord] = {}
        self._production_log: list[dict[str, str]] = []
        logger.info(
            "LitigationSupport initialized",
            case_number=case_number,
            bates_prefix=bates_prefix,
        )

    def _assign_bates_number(self) -> str:
        """Assign the next sequential Bates number.

        Returns:
            Formatted Bates number string (e.g., PROD000001).
        """
        bates = f"{self._bates_prefix}{self._bates_counter:07d}"
        self._bates_counter += 1
        return bates

    def _compute_file_hash(self, content: str) -> str:
        """Compute SHA-256 hash of document content.

        Args:
            content: Document text content.

        Returns:
            Hex-encoded SHA-256 hash.
        """
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _classify_tar(self, document_type: str, subject: str, custodian: str) -> tuple[float, str]:
        """Classify document responsiveness using TAR heuristics.

        Simulates a TAR model probability output based on document
        characteristics relevant to discovery requests.

        Args:
            document_type: Type of document.
            subject: Document subject or title.
            custodian: Document custodian.

        Returns:
            Tuple of (confidence_score, tier_label).
        """
        # Heuristic scoring: certain document types and keyword subjects
        # are more likely to be responsive in business litigation
        base_score = random.uniform(0.1, 0.9)

        # Boost for document types commonly responsive in commercial disputes
        if document_type in ("email", "memo", "contract"):
            base_score = min(1.0, base_score + 0.15)

        # Keywords that typically indicate responsiveness
        responsive_keywords = ["agreement", "contract", "payment", "dispute", "claim", "breach"]
        non_responsive_keywords = ["newsletter", "meeting minutes", "lunch", "social"]

        subject_lower = subject.lower()
        if any(kw in subject_lower for kw in responsive_keywords):
            base_score = min(1.0, base_score + 0.2)
        if any(kw in subject_lower for kw in non_responsive_keywords):
            base_score = max(0.0, base_score - 0.3)

        # Determine tier
        confidence = round(base_score, 3)
        tier = "uncertain"
        for tier_name, tier_data in _TAR_CONFIDENCE_TIERS.items():
            low, high = tier_data["probability_range"]
            if low <= confidence <= high:
                tier = tier_name
                break

        return confidence, tier

    def collect_document(
        self,
        custodian: str,
        document_type: str,
        subject: str,
        document_date: datetime,
        content_preview: str = "",
        privilege_tags: list[str] | None = None,
        is_redacted: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> DocumentRecord:
        """Collect and register a document for e-discovery.

        Assigns a Bates number, computes integrity hash, runs TAR
        classification, and registers the document in the case registry.

        Args:
            custodian: Custodian possessing this document.
            document_type: Type of document.
            subject: Document subject or title.
            document_date: Date of the document.
            content_preview: Short text preview for TAR heuristics.
            privilege_tags: Applied privilege designations.
            is_redacted: Whether the document has been redacted.
            metadata: Additional document metadata.

        Returns:
            Registered DocumentRecord with Bates number and TAR score.
        """
        document_id = str(uuid.uuid4())
        bates_number = self._assign_bates_number()
        file_hash = self._compute_file_hash(f"{document_id}{subject}{document_date.isoformat()}")
        tar_confidence, tar_tier = self._classify_tar(document_type, subject, custodian)
        applied_tags = privilege_tags or []
        is_privileged = len(applied_tags) > 0
        is_responsive = tar_tier in ("highly_responsive", "likely_responsive")

        record = DocumentRecord(
            document_id=document_id,
            bates_number=bates_number,
            custodian=custodian,
            document_type=document_type,
            document_date=document_date,
            subject=subject,
            file_hash=file_hash,
            is_privileged=is_privileged,
            privilege_tags=applied_tags,
            is_responsive=is_responsive,
            is_redacted=is_redacted,
            tar_confidence=tar_confidence,
            tar_tier=tar_tier,
            production_status="collected",
            metadata=metadata or {},
        )
        self._document_registry[document_id] = record

        logger.debug(
            "Document collected",
            document_id=document_id,
            bates_number=bates_number,
            custodian=custodian,
            tar_tier=tar_tier,
        )
        return record

    def collect_batch(
        self,
        custodians: list[str],
        document_count: int,
        date_range_start: datetime,
        date_range_end: datetime,
        document_types: list[str] | None = None,
        privilege_rate: float = 0.15,
    ) -> list[DocumentRecord]:
        """Collect a synthetic batch of documents for e-discovery.

        Args:
            custodians: List of custodian names.
            document_count: Total number of documents to collect.
            date_range_start: Start of relevant date range.
            date_range_end: End of relevant date range.
            document_types: Document types to generate; all types if None.
            privilege_rate: Fraction of documents to tag as privileged.

        Returns:
            List of collected DocumentRecord instances.
        """
        types = document_types or _EDISCOVERY_DOCUMENT_TYPES
        subjects = [
            "Re: Project Agreement Terms", "FW: Contract Negotiation",
            "Legal Review Required", "Confidential: Settlement Discussion",
            "Q3 Financial Projections", "Meeting Notes: Vendor Call",
            "Status Update", "Action Items from Today",
            "Re: Dispute Resolution Process", "Invoice #1042",
        ]

        time_range_seconds = int((date_range_end - date_range_start).total_seconds())
        records: list[DocumentRecord] = []

        for _ in range(document_count):
            custodian = random.choice(custodians)
            doc_type = random.choice(types)
            subject = random.choice(subjects)
            doc_seconds = random.randint(0, time_range_seconds)
            doc_date = date_range_start + __import__("datetime").timedelta(seconds=doc_seconds)
            tags: list[str] = []
            if random.random() < privilege_rate:
                tags = [random.choice(_PRIVILEGE_TAGS)]

            record = self.collect_document(
                custodian=custodian,
                document_type=doc_type,
                subject=subject,
                document_date=doc_date,
                privilege_tags=tags,
            )
            records.append(record)

        logger.info(
            "Batch document collection complete",
            document_count=len(records),
            case_number=self._case_number,
        )
        return records

    def apply_privilege_review(
        self, document_id: str, privilege_tags: list[str], reviewing_attorney: str
    ) -> DocumentRecord | None:
        """Apply privilege review tags to a document.

        Args:
            document_id: Document to update.
            privilege_tags: List of privilege designations to apply.
            reviewing_attorney: Name of attorney conducting review.

        Returns:
            Updated DocumentRecord, or None if not found.
        """
        record = self._document_registry.get(document_id)
        if record is None:
            logger.warning("Document not found for privilege review", document_id=document_id)
            return None

        record.privilege_tags = privilege_tags
        record.is_privileged = len(privilege_tags) > 0
        if record.is_privileged:
            record.production_status = "withheld_privilege"
        record.metadata["reviewing_attorney"] = reviewing_attorney
        record.metadata["review_timestamp"] = datetime.now(tz=timezone.utc).isoformat()

        logger.info(
            "Privilege review applied",
            document_id=document_id,
            is_privileged=record.is_privileged,
            reviewing_attorney=reviewing_attorney,
        )
        return record

    def identify_responsive_documents(
        self, confidence_threshold: float = 0.65
    ) -> list[DocumentRecord]:
        """Identify documents above the TAR confidence threshold.

        Args:
            confidence_threshold: Minimum TAR confidence to mark as responsive.

        Returns:
            List of responsive DocumentRecord instances.
        """
        responsive = [
            doc for doc in self._document_registry.values()
            if doc.tar_confidence >= confidence_threshold and not doc.is_privileged
        ]
        logger.info(
            "Responsive document identification",
            responsive_count=len(responsive),
            confidence_threshold=confidence_threshold,
        )
        return responsive

    def create_production(
        self,
        production_format: str = "concordance",
        include_privilege_log: bool = True,
    ) -> ProductionPackage:
        """Create a production package of responsive, non-privileged documents.

        Args:
            production_format: Output format (concordance, summation, native, pdf).
            include_privilege_log: Whether to generate a privilege log.

        Returns:
            ProductionPackage with production metadata and log.

        Raises:
            ValueError: If production_format is unsupported.
        """
        if production_format not in _PRODUCTION_FORMATS:
            raise ValueError(
                f"Unsupported format '{production_format}'. "
                f"Supported: {list(_PRODUCTION_FORMATS.keys())}"
            )

        production_id = str(uuid.uuid4())
        production_date = datetime.now(tz=timezone.utc)
        responsive_docs = self.identify_responsive_documents()

        if not responsive_docs:
            logger.warning(
                "No responsive documents to produce",
                case_number=self._case_number,
            )

        bates_start = responsive_docs[0].bates_number if responsive_docs else f"{self._bates_prefix}0000001"
        bates_end = responsive_docs[-1].bates_number if responsive_docs else bates_start
        total_pages = sum(random.randint(1, 20) for _ in responsive_docs)

        production_log: list[dict[str, str]] = []
        for doc in responsive_docs:
            doc.production_status = "produced"
            production_log.append({
                "document_id": doc.document_id,
                "bates_number": doc.bates_number,
                "custodian": doc.custodian,
                "document_type": doc.document_type,
                "document_date": doc.document_date.isoformat(),
                "subject": doc.subject,
                "file_hash": doc.file_hash,
            })

        self._production_log.extend(production_log)

        # Integrity hash of the manifest
        manifest_content = "|".join(entry["bates_number"] for entry in production_log)
        integrity_hash = hashlib.sha256(manifest_content.encode()).hexdigest()

        package = ProductionPackage(
            production_id=production_id,
            case_number=self._case_number,
            production_date=production_date,
            bates_range_start=bates_start,
            bates_range_end=bates_end,
            document_count=len(responsive_docs),
            format=production_format,
            privilege_log_included=include_privilege_log,
            total_pages=total_pages,
            production_log=production_log,
            integrity_hash=integrity_hash,
        )

        logger.info(
            "Production package created",
            production_id=production_id,
            case_number=self._case_number,
            document_count=len(responsive_docs),
            format=production_format,
        )
        return package

    def get_case_statistics(self) -> dict[str, Any]:
        """Return statistics for the current case collection.

        Returns:
            Dict with total counts, privilege rate, TAR tier distribution.
        """
        docs = list(self._document_registry.values())
        privileged = [d for d in docs if d.is_privileged]
        responsive = [d for d in docs if d.is_responsive]
        produced = [d for d in docs if d.production_status == "produced"]

        tier_distribution: dict[str, int] = {}
        for doc in docs:
            tier_distribution[doc.tar_tier] = tier_distribution.get(doc.tar_tier, 0) + 1

        return {
            "case_number": self._case_number,
            "total_collected": len(docs),
            "privileged_count": len(privileged),
            "privilege_rate": round(len(privileged) / max(1, len(docs)), 3),
            "responsive_count": len(responsive),
            "responsiveness_rate": round(len(responsive) / max(1, len(docs)), 3),
            "produced_count": len(produced),
            "tar_tier_distribution": tier_distribution,
            "custodians": list({d.custodian for d in docs}),
            "bates_counter": self._bates_counter,
        }

    def get_production_log(self) -> list[dict[str, str]]:
        """Return the full production log for audit purposes.

        Returns:
            List of production log entry dicts.
        """
        return list(self._production_log)


__all__ = ["LitigationSupport", "DocumentRecord", "ProductionPackage"]
