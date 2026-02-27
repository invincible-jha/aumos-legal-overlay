"""Privilege preserver adapter for aumos-legal-overlay.

Manages attorney-client privilege classification, privilege log generation,
inadvertent disclosure detection, clawback procedures, and redaction workflows.
"""

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


# Privilege type definitions and their legal bases
_PRIVILEGE_TYPES: dict[str, dict[str, Any]] = {
    "attorney_client": {
        "description": "Communication between attorney and client for legal advice.",
        "legal_basis": "Upjohn Co. v. United States, 449 U.S. 383 (1981)",
        "elements": [
            "communication_with_attorney",
            "confidential_nature",
            "legal_advice_sought",
            "client_intent_to_maintain_confidence",
        ],
        "waiver_risks": [
            "disclosure_to_third_parties",
            "crime_fraud_exception",
            "subject_matter_waiver",
        ],
    },
    "work_product": {
        "description": "Materials prepared in anticipation of litigation.",
        "legal_basis": "FRCP 26(b)(3); Hickman v. Taylor, 329 U.S. 495 (1947)",
        "elements": [
            "prepared_in_anticipation_of_litigation",
            "prepared_by_party_or_representative",
            "qualified_immunity",
        ],
        "waiver_risks": [
            "substantial_need_exception",
            "voluntary_disclosure",
        ],
    },
    "joint_defense": {
        "description": "Privilege over communications among co-defendants sharing common interest.",
        "legal_basis": "Restatement (Third) of the Law Governing Lawyers §76",
        "elements": [
            "common_legal_interest",
            "shared_defense_or_claim",
            "communication_in_furtherance",
        ],
        "waiver_risks": [
            "departure_from_joint_defense",
            "adverse_interests_arising",
        ],
    },
    "common_interest": {
        "description": "Privilege for parties sharing common legal interest without co-party status.",
        "legal_basis": "Restatement (Third) of the Law Governing Lawyers §76",
        "elements": [
            "common_legal_interest",
            "communication_between_counsel",
            "maintained_confidentiality",
        ],
        "waiver_risks": ["adverse_party_use", "non_attorney_disclosure"],
    },
}

# Redaction marker patterns
_REDACTION_MARKER = "[REDACTED — PRIVILEGED]"
_PRIVILEGE_HEADER = "PRIVILEGED AND CONFIDENTIAL\nATTORNEY-CLIENT COMMUNICATION\nNOT SUBJECT TO DISCLOSURE"

# Inadvertent disclosure indicator patterns
_INADVERTENT_DISCLOSURE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bprivileged\s+and\s+confidential\b", re.IGNORECASE),
    re.compile(r"\battorney.client\s+privilege\b", re.IGNORECASE),
    re.compile(r"\bwork\s+product\b", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+forward\b", re.IGNORECASE),
    re.compile(r"\bcounsel\s+only\b", re.IGNORECASE),
    re.compile(r"\bconfidential\s+legal\s+advice\b", re.IGNORECASE),
]

# Attorney name pattern (simplified — Esq., Attorney, Counsel markers)
_ATTORNEY_IDENTIFIER_PATTERN = re.compile(
    r"\b(?:Esq\.?|Attorney\s+at\s+Law|General\s+Counsel|Deputy\s+GC|Legal\s+Counsel)\b",
    re.IGNORECASE,
)


@dataclass
class PrivilegeClassification:
    """Result of classifying a document for privilege.

    Attributes:
        classification_id: Unique identifier for this classification.
        document_id: Document being classified.
        privilege_type: Classified privilege type, or None.
        is_privileged: Whether the document is privileged.
        confidence_score: Confidence in the privilege determination (0.0-1.0).
        elements_satisfied: Privilege elements found in the document.
        elements_missing: Privilege elements not found.
        waiver_risks_identified: Waiver risk factors detected.
        recommended_action: Recommended handling action.
        privilege_basis_text: Full legal basis text for the privilege log.
        reviewer_notes: Notes for attorney review.
    """

    classification_id: str
    document_id: str
    privilege_type: str | None
    is_privileged: bool
    confidence_score: float
    elements_satisfied: list[str]
    elements_missing: list[str]
    waiver_risks_identified: list[str]
    recommended_action: str
    privilege_basis_text: str
    reviewer_notes: str


@dataclass
class PrivilegeLogEntry:
    """A single privilege log entry compliant with FRCP 26(b)(5).

    Attributes:
        entry_id: Unique entry identifier.
        entry_number: Sequential entry number for the case.
        document_id: Document being logged.
        case_number: Associated case number.
        document_type: Type of document (email, memo, etc.).
        document_date: Date of the document.
        author: Document author name.
        recipients: List of recipients.
        privilege_type: Type of privilege claimed.
        privilege_basis: Legal basis for the privilege claim.
        subject_matter: General subject matter (without revealing privilege).
        is_redacted: Whether document is redacted vs. fully withheld.
        bates_number: Assigned Bates number if applicable.
        reviewing_attorney: Attorney who reviewed the document.
        review_date: Date of privilege review.
    """

    entry_id: str
    entry_number: int
    document_id: str
    case_number: str
    document_type: str
    document_date: datetime | None
    author: str | None
    recipients: list[str]
    privilege_type: str
    privilege_basis: str
    subject_matter: str
    is_redacted: bool
    bates_number: str | None
    reviewing_attorney: str
    review_date: datetime


@dataclass
class ClawbackRequest:
    """An inadvertent disclosure clawback request.

    Attributes:
        clawback_id: Unique clawback request identifier.
        original_document_id: Document inadvertently disclosed.
        recipient: Recipient of the inadvertent disclosure.
        disclosure_date: Date of inadvertent disclosure.
        discovery_date: Date the disclosure was discovered.
        privilege_type: Type of privilege covering the document.
        clawback_notice_text: Text of the clawback notice.
        status: Clawback request status (pending, acknowledged, returned, disputed).
        protective_order_reference: Reference to protective order if applicable.
    """

    clawback_id: str
    original_document_id: str
    recipient: str
    disclosure_date: datetime
    discovery_date: datetime
    privilege_type: str
    clawback_notice_text: str
    status: str
    protective_order_reference: str | None


class PrivilegePreserver:
    """Manages attorney-client privilege preservation workflows.

    Classifies documents for privilege, generates FRCP-compliant privilege
    logs, detects inadvertent disclosures, manages clawback procedures,
    assesses waiver risks, and automates document redaction.
    """

    def __init__(
        self,
        case_number: str,
        reviewing_firm: str,
        confidence_threshold: float = 0.70,
    ) -> None:
        """Initialize the privilege preserver for a case.

        Args:
            case_number: Associated legal case number.
            reviewing_firm: Name of the reviewing law firm.
            confidence_threshold: Minimum score to classify as privileged.
        """
        self._case_number = case_number
        self._reviewing_firm = reviewing_firm
        self._confidence_threshold = confidence_threshold
        self._privilege_log: list[PrivilegeLogEntry] = []
        self._clawback_requests: dict[str, ClawbackRequest] = {}
        self._log_entry_counter = 0
        logger.info(
            "PrivilegePreserver initialized",
            case_number=case_number,
            reviewing_firm=reviewing_firm,
        )

    def classify_document(
        self,
        document_id: str,
        document_text: str,
        document_type: str,
        author: str | None = None,
        recipients: list[str] | None = None,
    ) -> PrivilegeClassification:
        """Classify a document for attorney-client privilege.

        Analyzes document text for privilege indicators, identifies
        satisfied and missing privilege elements, and scores confidence.

        Args:
            document_id: Unique document identifier.
            document_text: Full text content of the document.
            document_type: Type of document (email, memo, contract, etc.).
            author: Document author name if known.
            recipients: List of recipients if applicable.

        Returns:
            PrivilegeClassification with full privilege analysis.
        """
        classification_id = str(uuid.uuid4())
        privilege_type = None
        elements_satisfied: list[str] = []
        elements_missing: list[str] = []
        waiver_risks: list[str] = []

        # Check for attorney identifier in author or recipients
        has_attorney = False
        all_parties = [author or ""] + (recipients or [])
        for party in all_parties:
            if _ATTORNEY_IDENTIFIER_PATTERN.search(party):
                has_attorney = True
                break

        # Check document text for attorney language
        text_matches = sum(
            1 for pattern in _INADVERTENT_DISCLOSURE_PATTERNS
            if pattern.search(document_text)
        )

        # Determine privilege type and satisfied elements
        if "work product" in document_text.lower() or "anticipation of litigation" in document_text.lower():
            privilege_type = "work_product"
            elements = _PRIVILEGE_TYPES["work_product"]["elements"]
            for element in elements:
                if element == "prepared_in_anticipation_of_litigation" and "litigation" in document_text.lower():
                    elements_satisfied.append(element)
                elif element == "prepared_by_party_or_representative" and author:
                    elements_satisfied.append(element)
                else:
                    elements_missing.append(element)
        elif has_attorney or text_matches >= 2:
            privilege_type = "attorney_client"
            elements = _PRIVILEGE_TYPES["attorney_client"]["elements"]
            if has_attorney:
                elements_satisfied.append("communication_with_attorney")
            else:
                elements_missing.append("communication_with_attorney")
            elements_satisfied.append("confidential_nature")
            if "advice" in document_text.lower() or "opinion" in document_text.lower():
                elements_satisfied.append("legal_advice_sought")
            else:
                elements_missing.append("legal_advice_sought")
            elements_satisfied.append("client_intent_to_maintain_confidence")

        # Check waiver risks
        if recipients and len(recipients) > 5:
            waiver_risks.append("Wide distribution may constitute waiver — review recipient list.")
        if "forwarded" in document_text.lower() and privilege_type:
            waiver_risks.append("Document was forwarded — check if forwarding waived privilege.")

        # Compute confidence score
        total_elements = len(elements_satisfied) + len(elements_missing)
        element_score = len(elements_satisfied) / max(1, total_elements)
        text_score = min(1.0, text_matches / 3)
        attorney_score = 0.3 if has_attorney else 0.0
        raw_confidence = (element_score * 0.5) + (text_score * 0.3) + attorney_score
        confidence = round(min(1.0, raw_confidence), 3)

        is_privileged = (
            privilege_type is not None
            and confidence >= self._confidence_threshold
        )

        if is_privileged and privilege_type:
            recommended_action = "withhold_from_production"
            privilege_basis = _PRIVILEGE_TYPES[privilege_type]["legal_basis"]
            reviewer_notes = (
                f"Classified as {privilege_type.replace('_', ' ')} with {confidence:.0%} confidence. "
                f"Elements satisfied: {', '.join(elements_satisfied)}. "
                + (f"Waiver risks: {'; '.join(waiver_risks)}" if waiver_risks else "No waiver risks detected.")
            )
        else:
            recommended_action = "produce" if not privilege_type else "attorney_review"
            privilege_basis = ""
            reviewer_notes = (
                "Privilege classification inconclusive. Attorney review recommended."
                if privilege_type else "No privilege indicators detected. Produce if responsive."
            )

        classification = PrivilegeClassification(
            classification_id=classification_id,
            document_id=document_id,
            privilege_type=privilege_type,
            is_privileged=is_privileged,
            confidence_score=confidence,
            elements_satisfied=elements_satisfied,
            elements_missing=elements_missing,
            waiver_risks_identified=waiver_risks,
            recommended_action=recommended_action,
            privilege_basis_text=privilege_basis,
            reviewer_notes=reviewer_notes,
        )

        logger.info(
            "Document privilege classification complete",
            classification_id=classification_id,
            document_id=document_id,
            privilege_type=privilege_type,
            is_privileged=is_privileged,
            confidence=confidence,
        )
        return classification

    def add_to_privilege_log(
        self,
        classification: PrivilegeClassification,
        document_type: str,
        subject_matter: str,
        reviewing_attorney: str,
        document_date: datetime | None = None,
        author: str | None = None,
        recipients: list[str] | None = None,
        bates_number: str | None = None,
        is_redacted: bool = False,
    ) -> PrivilegeLogEntry:
        """Add a classified privileged document to the privilege log.

        Generates a FRCP 26(b)(5)-compliant privilege log entry for the
        document, assigned the next sequential entry number.

        Args:
            classification: PrivilegeClassification for the document.
            document_type: Type of document for the log entry.
            subject_matter: Non-revealing subject matter description.
            reviewing_attorney: Attorney conducting the review.
            document_date: Date of the document.
            author: Document author.
            recipients: Document recipients.
            bates_number: Bates number if assigned.
            is_redacted: Whether document is redacted vs. fully withheld.

        Returns:
            Created PrivilegeLogEntry.
        """
        self._log_entry_counter += 1
        entry = PrivilegeLogEntry(
            entry_id=str(uuid.uuid4()),
            entry_number=self._log_entry_counter,
            document_id=classification.document_id,
            case_number=self._case_number,
            document_type=document_type,
            document_date=document_date,
            author=author,
            recipients=recipients or [],
            privilege_type=classification.privilege_type or "attorney_client",
            privilege_basis=classification.privilege_basis_text,
            subject_matter=subject_matter,
            is_redacted=is_redacted,
            bates_number=bates_number,
            reviewing_attorney=reviewing_attorney,
            review_date=datetime.now(tz=timezone.utc),
        )
        self._privilege_log.append(entry)

        logger.info(
            "Privilege log entry created",
            entry_id=entry.entry_id,
            entry_number=self._log_entry_counter,
            document_id=classification.document_id,
        )
        return entry

    def redact_document(
        self, document_text: str, privilege_type: str
    ) -> tuple[str, list[tuple[int, int]]]:
        """Apply automated redaction to a privileged document.

        Identifies and redacts legal advice content, privilege headers,
        and attorney communications.

        Args:
            document_text: Full text of the document to redact.
            privilege_type: The privilege type for redaction context.

        Returns:
            Tuple of (redacted_text, list of (start, end) redaction spans).
        """
        redacted = document_text
        spans: list[tuple[int, int]] = []

        # Redact privilege header block if present
        header_pattern = re.compile(
            r"(privileged\s+and\s+confidential[\s\S]{0,200}?)\n",
            re.IGNORECASE
        )
        for match in header_pattern.finditer(document_text):
            start, end = match.span()
            spans.append((start, end))

        # Redact attorney advice paragraphs
        advice_pattern = re.compile(
            r"((?:my|our)\s+(?:advice|recommendation|opinion)\s+is[\s\S]{0,500}?\.)\s",
            re.IGNORECASE
        )
        for match in advice_pattern.finditer(document_text):
            start, end = match.span(1)
            spans.append((start, end))

        # Apply redactions in reverse order (preserve offsets)
        spans_sorted = sorted(set(spans), key=lambda s: s[0], reverse=True)
        for start, end in spans_sorted:
            redacted = redacted[:start] + _REDACTION_MARKER + redacted[end:]

        logger.info(
            "Document redaction applied",
            privilege_type=privilege_type,
            redaction_count=len(spans),
        )
        return redacted, spans_sorted

    def detect_inadvertent_disclosure(
        self,
        document_id: str,
        document_text: str,
        disclosed_to: str,
    ) -> dict[str, Any]:
        """Detect if a document contains privileged content disclosed inadvertently.

        Args:
            document_id: Document identifier.
            document_text: Text of the document that was disclosed.
            disclosed_to: Recipient of the disclosure.

        Returns:
            Dict with is_inadvertent, privilege_indicators, and recommended_action.
        """
        privilege_hits: list[str] = []
        for pattern in _INADVERTENT_DISCLOSURE_PATTERNS:
            matches = pattern.findall(document_text)
            privilege_hits.extend(matches[:2])

        is_inadvertent = len(privilege_hits) >= 1

        logger.info(
            "Inadvertent disclosure detection",
            document_id=document_id,
            is_inadvertent=is_inadvertent,
            indicator_count=len(privilege_hits),
        )

        return {
            "document_id": document_id,
            "is_inadvertent_disclosure": is_inadvertent,
            "privilege_indicators_found": privilege_hits,
            "disclosed_to": disclosed_to,
            "recommended_action": (
                "Issue clawback notice immediately; preserve original document."
                if is_inadvertent
                else "No privilege indicators — disclosure appears non-privileged."
            ),
            "applicable_rule": "FRCP 26(b)(5)(B) — Clawback Procedure" if is_inadvertent else None,
        }

    def initiate_clawback(
        self,
        document_id: str,
        recipient: str,
        privilege_type: str,
        disclosure_date: datetime,
        protective_order_reference: str | None = None,
    ) -> ClawbackRequest:
        """Initiate a clawback request for an inadvertently disclosed document.

        Generates a formal clawback notice consistent with FRCP 26(b)(5)(B).

        Args:
            document_id: Inadvertently disclosed document.
            recipient: Recipient of the inadvertent disclosure.
            privilege_type: Privilege type covering the document.
            disclosure_date: Date the document was disclosed.
            protective_order_reference: Reference to a claw-back protective order.

        Returns:
            ClawbackRequest with formal notice text.
        """
        clawback_id = str(uuid.uuid4())
        discovery_date = datetime.now(tz=timezone.utc)

        privilege_label = _PRIVILEGE_TYPES.get(privilege_type, {}).get(
            "description", "privilege"
        )
        notice_text = (
            f"NOTICE OF INADVERTENT DISCLOSURE AND CLAWBACK REQUEST\n\n"
            f"Date: {discovery_date.strftime('%B %d, %Y')}\n"
            f"Document ID: {document_id}\n"
            f"Recipient: {recipient}\n\n"
            f"Dear Counsel:\n\n"
            f"We write to notify you that the document referenced above ({document_id}), "
            f"inadvertently disclosed to you on {disclosure_date.strftime('%B %d, %Y')}, "
            f"is protected by {privilege_label} and was produced in error.\n\n"
            f"Pursuant to Federal Rule of Civil Procedure 26(b)(5)(B), we hereby demand "
            f"that you: (1) immediately return, sequester, or destroy the specified "
            f"document and all copies; (2) not use or disclose the information until the "
            f"claim is resolved; and (3) promptly notify your client of our demand.\n\n"
            + (f"This demand is subject to the parties' Protective Order regarding "
               f"inadvertent disclosures ({protective_order_reference}).\n\n"
               if protective_order_reference else "")
            + "If you disagree with this privilege claim, you may promptly present the "
            f"document to the Court under seal for determination.\n\n"
            f"Sincerely,\n{self._reviewing_firm}"
        )

        request = ClawbackRequest(
            clawback_id=clawback_id,
            original_document_id=document_id,
            recipient=recipient,
            disclosure_date=disclosure_date,
            discovery_date=discovery_date,
            privilege_type=privilege_type,
            clawback_notice_text=notice_text,
            status="pending",
            protective_order_reference=protective_order_reference,
        )
        self._clawback_requests[clawback_id] = request

        logger.info(
            "Clawback request initiated",
            clawback_id=clawback_id,
            document_id=document_id,
            recipient=recipient,
            privilege_type=privilege_type,
        )
        return request

    def assess_waiver_risk(
        self,
        document_id: str,
        disclosure_circumstances: list[str],
        privilege_type: str,
    ) -> dict[str, Any]:
        """Assess the risk of privilege waiver for a document.

        Args:
            document_id: Document being assessed.
            disclosure_circumstances: List of circumstances surrounding disclosure.
            privilege_type: Claimed privilege type.

        Returns:
            Dict with risk_level, applicable_waiver_doctrines, and mitigation.
        """
        waiver_risks = _PRIVILEGE_TYPES.get(privilege_type, {}).get("waiver_risks", [])
        triggered_risks: list[str] = []

        for circumstance in disclosure_circumstances:
            circ_lower = circumstance.lower()
            for risk in waiver_risks:
                if risk.replace("_", " ") in circ_lower:
                    triggered_risks.append(risk)

        # Subject matter waiver risk (AT&T v. City of Erie)
        if any("email" in c.lower() for c in disclosure_circumstances) and privilege_type == "attorney_client":
            triggered_risks.append("subject_matter_waiver")

        risk_level = "high" if len(triggered_risks) >= 2 else "medium" if triggered_risks else "low"

        mitigation = [
            "File protective order to limit scope of any waiver finding.",
            "Seek quick-peek agreement or claw-back provision before production.",
        ] if triggered_risks else ["No immediate mitigation required; standard privilege protections apply."]

        logger.info(
            "Waiver risk assessment complete",
            document_id=document_id,
            privilege_type=privilege_type,
            risk_level=risk_level,
            triggered_risks=triggered_risks,
        )

        return {
            "document_id": document_id,
            "privilege_type": privilege_type,
            "risk_level": risk_level,
            "triggered_waiver_doctrines": triggered_risks,
            "disclosure_circumstances": disclosure_circumstances,
            "mitigation_recommendations": mitigation,
        }

    def export_privilege_log(self) -> list[dict[str, Any]]:
        """Export the privilege log as a list of dicts for court submission.

        Returns:
            List of privilege log entry dicts in FRCP 26(b)(5) format.
        """
        return [
            {
                "entry_number": entry.entry_number,
                "entry_id": entry.entry_id,
                "case_number": entry.case_number,
                "document_id": entry.document_id,
                "bates_number": entry.bates_number,
                "document_type": entry.document_type,
                "document_date": entry.document_date.isoformat() if entry.document_date else None,
                "author": entry.author,
                "recipients": entry.recipients,
                "privilege_type": entry.privilege_type,
                "privilege_basis": entry.privilege_basis,
                "subject_matter": entry.subject_matter,
                "is_redacted": entry.is_redacted,
                "reviewing_attorney": entry.reviewing_attorney,
                "review_date": entry.review_date.isoformat(),
            }
            for entry in sorted(self._privilege_log, key=lambda e: e.entry_number)
        ]

    def get_review_summary(self) -> dict[str, Any]:
        """Return a summary of the privilege review for the case.

        Returns:
            Dict with privilege log statistics and clawback status.
        """
        total = len(self._privilege_log)
        by_type: dict[str, int] = {}
        redacted_count = 0
        for entry in self._privilege_log:
            by_type[entry.privilege_type] = by_type.get(entry.privilege_type, 0) + 1
            if entry.is_redacted:
                redacted_count += 1

        return {
            "case_number": self._case_number,
            "reviewing_firm": self._reviewing_firm,
            "total_privileged_documents": total,
            "redacted_count": redacted_count,
            "withheld_count": total - redacted_count,
            "privilege_type_breakdown": by_type,
            "clawback_requests_initiated": len(self._clawback_requests),
            "clawback_pending": sum(
                1 for r in self._clawback_requests.values() if r.status == "pending"
            ),
        }


__all__ = [
    "PrivilegePreserver",
    "PrivilegeClassification",
    "PrivilegeLogEntry",
    "ClawbackRequest",
]
