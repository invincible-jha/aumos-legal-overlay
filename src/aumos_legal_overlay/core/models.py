"""SQLAlchemy ORM models for aumos-legal-overlay.

All tenant-scoped tables extend AumOSModel which provides:
  - id: UUID primary key
  - tenant_id: UUID (RLS-enforced)
  - created_at: datetime
  - updated_at: datetime

Table naming convention: lgl_{table_name}
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from aumos_common.database import AumOSModel


class PrivilegeCheck(AumOSModel):
    """Tracks attorney-client privilege preservation check results.

    Records the outcome of privilege analysis for synthetic data documents,
    ensuring privileged content is correctly identified and preserved.

    Table: lgl_privilege_checks
    """

    __tablename__ = "lgl_privilege_checks"

    document_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    document_type: Mapped[str] = mapped_column(String(100), nullable=False)
    privilege_type: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # attorney_client, work_product, common_interest
    is_privileged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    privilege_basis: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewing_attorney: Mapped[str | None] = mapped_column(String(255), nullable=True)
    review_timestamp: Mapped[datetime | None] = mapped_column(nullable=True)
    metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="pending"
    )  # pending, reviewed, appealed, final


class EDiscoveryJob(AumOSModel):
    """Tracks e-discovery synthetic data generation jobs.

    Manages the lifecycle of e-discovery data generation requests,
    including document sets, custodians, and date ranges.

    Table: lgl_ediscovery_jobs
    """

    __tablename__ = "lgl_ediscovery_jobs"

    case_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    case_number: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    custodians: Mapped[list] = mapped_column(ARRAY(String), nullable=False, default=list)
    date_range_start: Mapped[datetime | None] = mapped_column(nullable=True)
    date_range_end: Mapped[datetime | None] = mapped_column(nullable=True)
    document_types: Mapped[list] = mapped_column(ARRAY(String), nullable=False, default=list)
    document_count_requested: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    document_count_generated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="queued"
    )  # queued, processing, completed, failed
    output_location: Mapped[str | None] = mapped_column(String(512), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    job_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class AuditTrail(AumOSModel):
    """Court-admissible audit trail entries.

    Records every significant action with cryptographic integrity
    to support court-admissible chain of custody documentation.

    Table: lgl_audit_trails
    """

    __tablename__ = "lgl_audit_trails"

    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    actor_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # user, system, attorney, admin
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    action_timestamp: Mapped[datetime] = mapped_column(nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    action_detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    integrity_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256 hex
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)  # Chain linkage
    is_immutable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    legal_hold_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)


class PrivilegeLog(AumOSModel):
    """Automated privilege log entries for discovery responses.

    Generates structured privilege log entries compliant with
    Federal Rule of Civil Procedure 26(b)(5) requirements.

    Table: lgl_privilege_logs
    """

    __tablename__ = "lgl_privilege_logs"

    document_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    document_date: Mapped[datetime | None] = mapped_column(nullable=True)
    document_type: Mapped[str] = mapped_column(String(100), nullable=False)
    author: Mapped[str | None] = mapped_column(String(255), nullable=True)
    recipients: Mapped[list] = mapped_column(ARRAY(String), nullable=False, default=list)
    privilege_claimed: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # attorney_client, work_product, joint_defense
    privilege_description: Mapped[str] = mapped_column(Text, nullable=False)
    subject_matter: Mapped[str] = mapped_column(String(512), nullable=False)
    basis_for_claim: Mapped[str] = mapped_column(Text, nullable=False)
    privilege_check_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    case_number: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    log_entry_number: Mapped[int] = mapped_column(Integer, nullable=False)
    is_redacted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class LegalHold(AumOSModel):
    """Legal hold tracking for preservation obligations.

    Manages legal hold notices, custodian acknowledgements,
    and preservation status for litigation readiness.

    Table: lgl_legal_holds
    """

    __tablename__ = "lgl_legal_holds"

    hold_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    case_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    case_number: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    matter_type: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # litigation, investigation, regulatory, arbitration
    issuing_attorney: Mapped[str] = mapped_column(String(255), nullable=False)
    custodians: Mapped[list] = mapped_column(ARRAY(String), nullable=False, default=list)
    custodian_acknowledgements: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    data_sources: Mapped[list] = mapped_column(ARRAY(String), nullable=False, default=list)
    hold_issued_at: Mapped[datetime] = mapped_column(nullable=False)
    hold_expires_at: Mapped[datetime | None] = mapped_column(nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="active"
    )  # active, released, suspended, expired
    last_reminder_sent_at: Mapped[datetime | None] = mapped_column(nullable=True)
    release_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    hold_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


__all__ = [
    "PrivilegeCheck",
    "EDiscoveryJob",
    "AuditTrail",
    "PrivilegeLog",
    "LegalHold",
]
