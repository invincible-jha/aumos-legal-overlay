"""Document production set management with Bates numbering.

GAP-315: Production Set Management with Bates Numbering.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


@dataclass
class ProductionDocument:
    """A single document in a production set with Bates number assigned."""

    document_id: str
    bates_number: str
    original_filename: str
    document_type: str
    privilege_status: str  # produced | withheld | redacted
    redaction_applied: bool = False
    production_notes: str = ""


@dataclass
class ProductionSet:
    """FRCP 34-compliant document production set.

    Bates numbers are sequential with a configurable prefix (e.g. ACME00001).
    FRCP Rule 34(b)(2)(E) requires production in a form in which it is
    ordinarily maintained or in a reasonably usable form.
    """

    production_set_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_number: str = ""
    requesting_party: str = ""
    producing_party: str = ""
    bates_prefix: str = "PROD"
    bates_start: int = 1
    bates_padding: int = 5
    documents: list[ProductionDocument] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "draft"  # draft | finalized | served
    total_documents: int = 0
    total_produced: int = 0
    total_withheld: int = 0


class ProductionManager:
    """Manages FRCP 34-compliant document production sets.

    Provides sequential Bates numbering, production/withhold tracking,
    and production set finalization per FRCP Rule 34 requirements.

    Bates format: {PREFIX}{SEQUENCE_NUMBER} where sequence is zero-padded
    to the configured padding width (default 5 digits = 00001-99999).
    """

    def create_production_set(
        self,
        case_number: str,
        requesting_party: str,
        producing_party: str,
        bates_prefix: str = "PROD",
        bates_start: int = 1,
        bates_padding: int = 5,
    ) -> ProductionSet:
        """Create a new FRCP 34 production set.

        Args:
            case_number: Court case number for identification.
            requesting_party: Party requesting production.
            producing_party: Party producing documents.
            bates_prefix: Bates stamp prefix (e.g. "ACME" -> "ACME00001").
            bates_start: Starting sequence number.
            bates_padding: Zero-padding width for sequence number.

        Returns:
            New ProductionSet instance.
        """
        production_set = ProductionSet(
            case_number=case_number,
            requesting_party=requesting_party,
            producing_party=producing_party,
            bates_prefix=bates_prefix.upper(),
            bates_start=bates_start,
            bates_padding=bates_padding,
        )
        logger.info(
            "production_set_created",
            set_id=production_set.production_set_id,
            case_number=case_number,
            bates_prefix=bates_prefix,
        )
        return production_set

    def assign_bates_numbers(
        self,
        production_set: ProductionSet,
        documents: list[dict[str, Any]],
    ) -> ProductionSet:
        """Assign sequential Bates numbers to documents and add to production set.

        Args:
            production_set: Target production set.
            documents: List of document dicts with document_id, filename, type, privilege_status.

        Returns:
            Updated ProductionSet with Bates-numbered documents.
        """
        current_sequence = production_set.bates_start + len(production_set.documents)

        for doc in documents:
            bates_number = self._format_bates(
                production_set.bates_prefix,
                current_sequence,
                production_set.bates_padding,
            )
            privilege_status = doc.get("privilege_status", "produced")
            production_doc = ProductionDocument(
                document_id=doc.get("document_id", str(uuid.uuid4())),
                bates_number=bates_number,
                original_filename=doc.get("filename", "unknown"),
                document_type=doc.get("document_type", "unknown"),
                privilege_status=privilege_status,
                redaction_applied=doc.get("redaction_applied", False),
                production_notes=doc.get("notes", ""),
            )
            production_set.documents.append(production_doc)
            current_sequence += 1

        production_set.total_documents = len(production_set.documents)
        production_set.total_produced = sum(
            1 for d in production_set.documents if d.privilege_status == "produced"
        )
        production_set.total_withheld = sum(
            1 for d in production_set.documents if d.privilege_status == "withheld"
        )

        logger.info(
            "bates_numbers_assigned",
            set_id=production_set.production_set_id,
            count=len(documents),
            produced=production_set.total_produced,
            withheld=production_set.total_withheld,
        )
        return production_set

    def finalize_production(self, production_set: ProductionSet) -> ProductionSet:
        """Finalize a production set for service on requesting party.

        Args:
            production_set: Production set to finalize.

        Returns:
            Finalized ProductionSet (status: finalized).

        Raises:
            ValueError: If production set has no documents.
        """
        if not production_set.documents:
            raise ValueError("Cannot finalize an empty production set.")
        production_set.status = "finalized"
        logger.info(
            "production_set_finalized",
            set_id=production_set.production_set_id,
            total_documents=production_set.total_documents,
        )
        return production_set

    @staticmethod
    def _format_bates(prefix: str, sequence: int, padding: int) -> str:
        """Format a Bates number string.

        Args:
            prefix: Bates prefix (e.g. "ACME").
            sequence: Sequential number.
            padding: Zero-padding width.

        Returns:
            Formatted Bates number (e.g. "ACME00001").
        """
        return f"{prefix}{str(sequence).zfill(padding)}"
