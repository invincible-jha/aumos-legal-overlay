"""Legal hold manager adapter for aumos-legal-overlay.

Manages legal hold lifecycle: notice generation and distribution, custodian
tracking, acknowledgement management, hold release, compliance monitoring,
audit trail generation, and regulatory obligation mapping.
"""

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


# Regulatory obligations that trigger legal hold requirements
_REGULATORY_HOLD_OBLIGATIONS: dict[str, dict[str, Any]] = {
    "FRCP_37e": {
        "description": "Federal Rules of Civil Procedure Rule 37(e) — ESI preservation.",
        "trigger": "Reasonable anticipation of litigation",
        "scope": "Electronically stored information (ESI)",
        "penalty": "Sanctions up to case dismissal for bad-faith spoliation.",
        "preservation_period": "Duration of litigation + appeals",
    },
    "SOX_802": {
        "description": "Sarbanes-Oxley Act Section 802 — Document retention.",
        "trigger": "Federal investigation or audit",
        "scope": "Financial records, audit workpapers",
        "penalty": "Up to 20 years imprisonment; $5M fine for individuals.",
        "preservation_period": "7 years minimum",
    },
    "HIPAA_164_530": {
        "description": "HIPAA §164.530 — Administrative requirements.",
        "trigger": "Regulatory inquiry or litigation",
        "scope": "Protected health information (PHI)",
        "penalty": "$100 to $1.9M per violation category per year.",
        "preservation_period": "6 years",
    },
    "FINRA_4511": {
        "description": "FINRA Rule 4511 — Record retention.",
        "trigger": "FINRA investigation or customer complaint",
        "scope": "Communications, order records, financial statements",
        "penalty": "Fines, suspension, bar from securities industry.",
        "preservation_period": "6 years",
    },
    "GDPR_Art_17": {
        "description": "GDPR Article 17 — Right to erasure (conflicts with hold obligations).",
        "trigger": "Ongoing litigation or legal claims",
        "scope": "Personal data relevant to the legal claim",
        "penalty": "Up to €20M or 4% of global turnover.",
        "preservation_period": "Duration of legal claim — overrides erasure requests.",
    },
}

# Matter type definitions
_MATTER_TYPES: dict[str, dict[str, Any]] = {
    "litigation": {
        "description": "Active or reasonably anticipated civil litigation",
        "standard_duration_days": 730,
        "regulatory_triggers": ["FRCP_37e"],
    },
    "government_investigation": {
        "description": "Federal, state, or regulatory government investigation",
        "standard_duration_days": 1095,
        "regulatory_triggers": ["FRCP_37e", "SOX_802"],
    },
    "internal_investigation": {
        "description": "Internal corporate investigation",
        "standard_duration_days": 180,
        "regulatory_triggers": ["SOX_802"],
    },
    "regulatory_inquiry": {
        "description": "Inquiry from regulatory body (SEC, FINRA, FTC, etc.)",
        "standard_duration_days": 365,
        "regulatory_triggers": ["FINRA_4511", "SOX_802"],
    },
    "mergers_and_acquisitions": {
        "description": "M&A due diligence and related matters",
        "standard_duration_days": 180,
        "regulatory_triggers": [],
    },
}

# Notice templates by matter type
_NOTICE_TEMPLATES: dict[str, str] = {
    "litigation": (
        "LEGAL HOLD NOTICE\n\n"
        "DATE: {issued_date}\n"
        "TO: {custodian_name}\n"
        "FROM: {issuing_attorney}, {issuing_firm}\n"
        "RE: Legal Hold — {case_name} ({case_number})\n\n"
        "IMMEDIATE ACTION REQUIRED\n\n"
        "You are required to preserve all documents and electronically stored information "
        "(ESI) in your possession, custody, or control that may be relevant to the "
        "above-referenced matter.\n\n"
        "WHAT YOU MUST PRESERVE:\n"
        "{data_sources_list}\n\n"
        "WHAT YOU MUST NOT DO:\n"
        "- Do not delete, destroy, modify, or overwrite any potentially relevant documents.\n"
        "- Do not allow automatic deletion policies to run on relevant data.\n"
        "- Do not move documents from their current locations without legal approval.\n\n"
        "This hold supersedes any routine document retention or deletion schedules.\n\n"
        "ACKNOWLEDGEMENT REQUIRED: Please sign and return the attached acknowledgement "
        "form within 5 business days.\n\n"
        "Questions: Contact {issuing_attorney} at {issuing_firm}.\n"
    ),
    "government_investigation": (
        "LEGAL HOLD NOTICE — GOVERNMENT INVESTIGATION\n\n"
        "DATE: {issued_date}\n"
        "CONFIDENTIAL — ATTORNEY-CLIENT PRIVILEGED\n\n"
        "TO: {custodian_name}\n"
        "FROM: {issuing_attorney}, {issuing_firm}\n"
        "RE: Preservation Notice — {case_name}\n\n"
        "STRICTLY CONFIDENTIAL\n\n"
        "We are writing on behalf of the company in connection with a government investigation. "
        "You must immediately preserve all documents and ESI that may be relevant, including:\n\n"
        "{data_sources_list}\n\n"
        "You must not discuss this notice or the subject matter of the investigation with "
        "anyone outside the company or legal counsel without authorization.\n\n"
        "ACKNOWLEDGE RECEIPT within 2 business days.\n\n"
        "Issued by: {issuing_attorney}\n"
    ),
    "default": (
        "LEGAL HOLD NOTICE\n\n"
        "DATE: {issued_date}\n"
        "TO: {custodian_name}\n"
        "FROM: {issuing_attorney}\n"
        "RE: {case_name} — Document Preservation\n\n"
        "You are required to preserve all documents related to {case_name}.\n"
        "Data sources covered: {data_sources_list}\n\n"
        "Please acknowledge receipt of this notice within 5 business days.\n"
    ),
}


@dataclass
class CustodianRecord:
    """Tracking record for a legal hold custodian.

    Attributes:
        custodian_id: Unique custodian identifier.
        custodian_name: Name of the custodian.
        hold_id: Associated legal hold identifier.
        notice_sent_at: When the hold notice was sent.
        acknowledged_at: When the custodian acknowledged the hold.
        reminder_count: Number of reminder notices sent.
        last_reminder_at: Timestamp of most recent reminder.
        status: Custodian compliance status (pending, acknowledged, overdue).
        data_sources: Data sources the custodian is responsible for preserving.
    """

    custodian_id: str
    custodian_name: str
    hold_id: str
    notice_sent_at: datetime
    acknowledged_at: datetime | None
    reminder_count: int
    last_reminder_at: datetime | None
    status: str
    data_sources: list[str]


@dataclass
class LegalHoldRecord:
    """Full legal hold record managed by LegalHoldManager.

    Attributes:
        hold_id: Unique hold identifier.
        hold_name: Descriptive name for the hold.
        case_name: Associated legal matter name.
        case_number: Official case number.
        matter_type: Type of legal matter.
        issuing_attorney: Attorney issuing the hold.
        custodian_records: Per-custodian tracking records.
        data_sources: Data sources subject to the hold.
        issued_at: Timestamp of hold issuance.
        expires_at: Hold expiration date if applicable.
        released_at: Timestamp of hold release.
        release_reason: Reason for hold release.
        status: Hold status (active, released, expired).
        regulatory_obligations: Applicable regulatory frameworks.
        audit_trail: Ordered list of audit events for this hold.
    """

    hold_id: str
    hold_name: str
    case_name: str
    case_number: str | None
    matter_type: str
    issuing_attorney: str
    custodian_records: list[CustodianRecord]
    data_sources: list[str]
    issued_at: datetime
    expires_at: datetime | None
    released_at: datetime | None
    release_reason: str | None
    status: str
    regulatory_obligations: list[str]
    audit_trail: list[dict[str, Any]] = field(default_factory=list)


class LegalHoldManager:
    """Manages the full lifecycle of legal holds.

    Generates and distributes hold notices, tracks custodian acknowledgements,
    monitors compliance, manages hold releases, generates audit trails, and
    maps holds to regulatory preservation obligations.
    """

    def __init__(
        self,
        issuing_firm: str,
        acknowledgement_deadline_days: int = 5,
        reminder_interval_days: int = 7,
        overdue_threshold_days: int = 14,
    ) -> None:
        """Initialize the legal hold manager.

        Args:
            issuing_firm: Name of the law firm issuing holds.
            acknowledgement_deadline_days: Days before acknowledgement is overdue.
            reminder_interval_days: Days between reminder notices.
            overdue_threshold_days: Days before custodian is escalated as non-compliant.
        """
        self._issuing_firm = issuing_firm
        self._ack_deadline_days = acknowledgement_deadline_days
        self._reminder_interval_days = reminder_interval_days
        self._overdue_threshold_days = overdue_threshold_days
        self._holds: dict[str, LegalHoldRecord] = {}
        logger.info(
            "LegalHoldManager initialized",
            issuing_firm=issuing_firm,
            ack_deadline_days=acknowledgement_deadline_days,
        )

    def generate_hold_notice(
        self,
        custodian_name: str,
        issuing_attorney: str,
        case_name: str,
        matter_type: str,
        data_sources: list[str],
        case_number: str | None = None,
    ) -> str:
        """Generate a formatted legal hold notice for a custodian.

        Args:
            custodian_name: Name of the custodian receiving the notice.
            issuing_attorney: Attorney issuing the hold.
            case_name: Name of the legal matter.
            matter_type: Type of matter (litigation, investigation, etc.).
            data_sources: Data sources to be preserved.
            case_number: Optional case number.

        Returns:
            Formatted legal hold notice text.
        """
        template = _NOTICE_TEMPLATES.get(matter_type, _NOTICE_TEMPLATES["default"])
        issued_date = datetime.now(tz=timezone.utc).strftime("%B %d, %Y")
        data_sources_list = "\n".join(f"  - {source}" for source in data_sources)

        notice = template.format(
            issued_date=issued_date,
            custodian_name=custodian_name,
            issuing_attorney=issuing_attorney,
            issuing_firm=self._issuing_firm,
            case_name=case_name,
            case_number=case_number or "N/A",
            data_sources_list=data_sources_list,
        )
        return notice

    def create_hold(
        self,
        hold_name: str,
        case_name: str,
        matter_type: str,
        issuing_attorney: str,
        custodians: list[str],
        data_sources: list[str],
        case_number: str | None = None,
        custom_expiry_days: int | None = None,
    ) -> LegalHoldRecord:
        """Create a new legal hold and issue notices to all custodians.

        Args:
            hold_name: Descriptive name for this hold.
            case_name: Name of the associated legal matter.
            matter_type: Type of matter (litigation, government_investigation, etc.).
            issuing_attorney: Attorney issuing the hold.
            custodians: List of custodian names to hold.
            data_sources: Data sources subject to preservation.
            case_number: Official case number.
            custom_expiry_days: Override the standard duration for this matter type.

        Returns:
            Created LegalHoldRecord with custodian tracking records.

        Raises:
            ValueError: If matter_type is not supported.
        """
        if matter_type not in _MATTER_TYPES:
            raise ValueError(
                f"Unsupported matter_type '{matter_type}'. "
                f"Supported: {list(_MATTER_TYPES.keys())}"
            )

        hold_id = str(uuid.uuid4())
        issued_at = datetime.now(tz=timezone.utc)
        matter_config = _MATTER_TYPES[matter_type]

        duration_days = custom_expiry_days or matter_config["standard_duration_days"]
        expires_at = issued_at + timedelta(days=duration_days)

        regulatory_obligations = matter_config.get("regulatory_triggers", [])

        custodian_records: list[CustodianRecord] = []
        audit_trail: list[dict[str, Any]] = []

        for custodian_name in custodians:
            notice = self.generate_hold_notice(
                custodian_name=custodian_name,
                issuing_attorney=issuing_attorney,
                case_name=case_name,
                matter_type=matter_type,
                data_sources=data_sources,
                case_number=case_number,
            )
            custodian_record = CustodianRecord(
                custodian_id=str(uuid.uuid4()),
                custodian_name=custodian_name,
                hold_id=hold_id,
                notice_sent_at=issued_at,
                acknowledged_at=None,
                reminder_count=0,
                last_reminder_at=None,
                status="pending",
                data_sources=data_sources,
            )
            custodian_records.append(custodian_record)
            audit_trail.append({
                "event": "hold_notice_issued",
                "timestamp": issued_at.isoformat(),
                "custodian": custodian_name,
                "notice_hash": hashlib.sha256(notice.encode()).hexdigest()[:16],
            })

        hold = LegalHoldRecord(
            hold_id=hold_id,
            hold_name=hold_name,
            case_name=case_name,
            case_number=case_number,
            matter_type=matter_type,
            issuing_attorney=issuing_attorney,
            custodian_records=custodian_records,
            data_sources=data_sources,
            issued_at=issued_at,
            expires_at=expires_at,
            released_at=None,
            release_reason=None,
            status="active",
            regulatory_obligations=regulatory_obligations,
            audit_trail=audit_trail,
        )
        self._holds[hold_id] = hold

        logger.info(
            "Legal hold created",
            hold_id=hold_id,
            hold_name=hold_name,
            matter_type=matter_type,
            custodian_count=len(custodians),
            regulatory_obligations=regulatory_obligations,
        )
        return hold

    def record_acknowledgement(
        self, hold_id: str, custodian_name: str
    ) -> CustodianRecord | None:
        """Record a custodian's acknowledgement of a legal hold notice.

        Args:
            hold_id: Hold identifier.
            custodian_name: Name of the acknowledging custodian.

        Returns:
            Updated CustodianRecord, or None if not found.
        """
        hold = self._holds.get(hold_id)
        if not hold:
            logger.warning("Hold not found for acknowledgement", hold_id=hold_id)
            return None

        now = datetime.now(tz=timezone.utc)
        for record in hold.custodian_records:
            if record.custodian_name == custodian_name and record.acknowledged_at is None:
                record.acknowledged_at = now
                record.status = "acknowledged"
                hold.audit_trail.append({
                    "event": "acknowledgement_received",
                    "timestamp": now.isoformat(),
                    "custodian": custodian_name,
                })
                logger.info(
                    "Hold acknowledgement recorded",
                    hold_id=hold_id,
                    custodian_name=custodian_name,
                )
                return record

        logger.warning(
            "Custodian not found or already acknowledged",
            hold_id=hold_id,
            custodian_name=custodian_name,
        )
        return None

    def send_reminder(self, hold_id: str, custodian_name: str) -> str | None:
        """Send a reminder notice to a non-acknowledging custodian.

        Args:
            hold_id: Hold identifier.
            custodian_name: Custodian to remind.

        Returns:
            Reminder notice text, or None if custodian already acknowledged.
        """
        hold = self._holds.get(hold_id)
        if not hold:
            return None

        now = datetime.now(tz=timezone.utc)
        for record in hold.custodian_records:
            if record.custodian_name == custodian_name and not record.acknowledged_at:
                record.reminder_count += 1
                record.last_reminder_at = now
                if record.reminder_count >= 3:
                    record.status = "overdue"

                hold.audit_trail.append({
                    "event": "reminder_sent",
                    "timestamp": now.isoformat(),
                    "custodian": custodian_name,
                    "reminder_count": record.reminder_count,
                })

                reminder_text = (
                    f"REMINDER #{record.reminder_count} — LEGAL HOLD NOTICE\n\n"
                    f"Date: {now.strftime('%B %d, %Y')}\n"
                    f"To: {custodian_name}\n"
                    f"Re: {hold.case_name} — Hold Acknowledgement Overdue\n\n"
                    f"This is a reminder that you have not yet acknowledged receipt "
                    f"of the Legal Hold Notice issued on "
                    f"{hold.issued_at.strftime('%B %d, %Y')}.\n\n"
                    f"Failure to acknowledge may be reported to senior management. "
                    f"Please acknowledge immediately.\n\n"
                    f"Issued by: {hold.issuing_attorney}, {self._issuing_firm}"
                )
                logger.info(
                    "Hold reminder sent",
                    hold_id=hold_id,
                    custodian_name=custodian_name,
                    reminder_count=record.reminder_count,
                )
                return reminder_text
        return None

    def release_hold(
        self, hold_id: str, release_reason: str, releasing_attorney: str
    ) -> LegalHoldRecord | None:
        """Release an active legal hold.

        Args:
            hold_id: Hold identifier to release.
            release_reason: Documented reason for release.
            releasing_attorney: Attorney authorizing the release.

        Returns:
            Updated LegalHoldRecord with released status, or None if not found.
        """
        hold = self._holds.get(hold_id)
        if not hold:
            logger.warning("Hold not found for release", hold_id=hold_id)
            return None

        now = datetime.now(tz=timezone.utc)
        hold.status = "released"
        hold.released_at = now
        hold.release_reason = release_reason
        hold.audit_trail.append({
            "event": "hold_released",
            "timestamp": now.isoformat(),
            "releasing_attorney": releasing_attorney,
            "release_reason": release_reason,
        })

        logger.info(
            "Legal hold released",
            hold_id=hold_id,
            release_reason=release_reason,
            releasing_attorney=releasing_attorney,
        )
        return hold

    def monitor_compliance(self) -> dict[str, Any]:
        """Check compliance status across all active holds.

        Returns:
            Dict with compliance summary, overdue custodians, and non-compliant holds.
        """
        now = datetime.now(tz=timezone.utc)
        compliance_summary: dict[str, Any] = {
            "total_active_holds": 0,
            "fully_compliant_holds": 0,
            "holds_with_overdue_custodians": 0,
            "total_pending_acknowledgements": 0,
            "total_overdue_custodians": 0,
            "overdue_custodian_list": [],
        }

        for hold in self._holds.values():
            if hold.status != "active":
                continue
            compliance_summary["total_active_holds"] += 1

            pending = [c for c in hold.custodian_records if c.status == "pending"]
            overdue = []
            for c in pending:
                days_since_notice = (now - c.notice_sent_at).days
                if days_since_notice >= self._overdue_threshold_days:
                    c.status = "overdue"
                    overdue.append(c.custodian_name)
                    compliance_summary["overdue_custodian_list"].append({
                        "hold_id": hold.hold_id,
                        "hold_name": hold.hold_name,
                        "custodian": c.custodian_name,
                        "days_overdue": days_since_notice - self._ack_deadline_days,
                    })

            compliance_summary["total_pending_acknowledgements"] += len(pending)
            compliance_summary["total_overdue_custodians"] += len(overdue)

            if not pending and not overdue:
                compliance_summary["fully_compliant_holds"] += 1
            elif overdue:
                compliance_summary["holds_with_overdue_custodians"] += 1

        logger.info(
            "Hold compliance monitoring complete",
            active_holds=compliance_summary["total_active_holds"],
            overdue_custodians=compliance_summary["total_overdue_custodians"],
        )
        return compliance_summary

    def get_regulatory_obligations(self, matter_type: str) -> list[dict[str, Any]]:
        """Return regulatory preservation obligations for a matter type.

        Args:
            matter_type: Matter type identifier.

        Returns:
            List of applicable regulatory obligation dicts.
        """
        obligation_ids = _MATTER_TYPES.get(matter_type, {}).get("regulatory_triggers", [])
        return [
            {"obligation_id": oid, **_REGULATORY_HOLD_OBLIGATIONS.get(oid, {})}
            for oid in obligation_ids
        ]

    def get_hold_audit_trail(self, hold_id: str) -> list[dict[str, Any]]:
        """Return the full audit trail for a specific hold.

        Args:
            hold_id: Hold identifier.

        Returns:
            Ordered list of audit event dicts.
        """
        hold = self._holds.get(hold_id)
        if not hold:
            return []
        return list(hold.audit_trail)

    def export_hold_summary(self, hold_id: str) -> dict[str, Any]:
        """Export a comprehensive summary of a legal hold.

        Args:
            hold_id: Hold identifier.

        Returns:
            Dict with full hold details, custodian status, and regulatory obligations.
        """
        hold = self._holds.get(hold_id)
        if not hold:
            return {"error": f"Hold '{hold_id}' not found."}

        acknowledged_count = sum(
            1 for c in hold.custodian_records if c.acknowledged_at is not None
        )

        return {
            "hold_id": hold.hold_id,
            "hold_name": hold.hold_name,
            "case_name": hold.case_name,
            "case_number": hold.case_number,
            "matter_type": hold.matter_type,
            "issuing_attorney": hold.issuing_attorney,
            "status": hold.status,
            "issued_at": hold.issued_at.isoformat(),
            "expires_at": hold.expires_at.isoformat() if hold.expires_at else None,
            "released_at": hold.released_at.isoformat() if hold.released_at else None,
            "release_reason": hold.release_reason,
            "total_custodians": len(hold.custodian_records),
            "acknowledged_custodians": acknowledged_count,
            "compliance_rate": round(acknowledged_count / max(1, len(hold.custodian_records)), 3),
            "data_sources": hold.data_sources,
            "regulatory_obligations": [
                {"id": oid, **_REGULATORY_HOLD_OBLIGATIONS.get(oid, {})}
                for oid in hold.regulatory_obligations
            ],
            "custodian_statuses": [
                {
                    "name": c.custodian_name,
                    "status": c.status,
                    "notice_sent_at": c.notice_sent_at.isoformat(),
                    "acknowledged_at": c.acknowledged_at.isoformat() if c.acknowledged_at else None,
                    "reminder_count": c.reminder_count,
                }
                for c in hold.custodian_records
            ],
            "audit_event_count": len(hold.audit_trail),
        }


__all__ = ["LegalHoldManager", "LegalHoldRecord", "CustodianRecord"]
