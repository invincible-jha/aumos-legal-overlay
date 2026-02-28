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

from sqlalchemy import Boolean, Date, Float, Integer, Numeric, String, Text
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


class TARProject(AumOSModel):
    """Technology-Assisted Review project tracking CAL lifecycle.

    Manages the full TAR/CAL workflow from seed collection through
    TREC Total Recall validation and elusion testing.

    Table: lgl_tar_projects
    """

    __tablename__ = "lgl_tar_projects"

    case_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    case_number: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    ediscovery_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="seed_collection"
    )  # seed_collection | training | review | validated
    target_recall: Mapped[float] = mapped_column(Float, nullable=False, default=0.85)
    estimated_recall: Mapped[float | None] = mapped_column(Float, nullable=True)
    corpus_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reviewed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    relevant_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    elusion_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    elusion_passes_threshold: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    model_accuracy: Mapped[float | None] = mapped_column(Float, nullable=True)
    project_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class TARBatch(AumOSModel):
    """A review batch within a TAR project.

    Records each ranked batch of documents sent to reviewers
    for relevance judgments under the CAL protocol.

    Table: lgl_tar_batches
    """

    __tablename__ = "lgl_tar_batches"

    tar_project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    batch_number: Mapped[int] = mapped_column(Integer, nullable=False)
    batch_size: Mapped[int] = mapped_column(Integer, nullable=False)
    reviewer_user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="pending"
    )  # pending | in_review | completed
    document_ids: Mapped[list] = mapped_column(ARRAY(String), nullable=False, default=list)
    relevance_scores: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)


class TARDocumentReview(AumOSModel):
    """Individual relevance judgment for a document in TAR review.

    Table: lgl_tar_document_reviews
    """

    __tablename__ = "lgl_tar_document_reviews"

    tar_project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    tar_batch_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    document_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    predicted_relevance_score: Mapped[float] = mapped_column(Float, nullable=False)
    reviewer_user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_relevant: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    reviewer_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    is_seed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class LGLProductionSet(AumOSModel):
    """FRCP 34-compliant document production set with Bates numbering.

    Table: lgl_production_sets
    """

    __tablename__ = "lgl_production_sets"

    case_number: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    requesting_party: Mapped[str] = mapped_column(String(255), nullable=False)
    producing_party: Mapped[str] = mapped_column(String(255), nullable=False)
    bates_prefix: Mapped[str] = mapped_column(String(20), nullable=False)
    bates_start: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    bates_padding: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="draft"
    )  # draft | finalized | served
    total_documents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_produced: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_withheld: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    production_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class LGLProductionDocument(AumOSModel):
    """A single document in a production set with Bates number assigned.

    Table: lgl_production_documents
    """

    __tablename__ = "lgl_production_documents"

    production_set_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    document_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    bates_number: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    document_type: Mapped[str] = mapped_column(String(100), nullable=False)
    privilege_status: Mapped[str] = mapped_column(
        String(30), nullable=False
    )  # produced | withheld | redacted
    redaction_applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    production_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")


class EDiscoveryRedaction(AumOSModel):
    """PII redaction record for a document.

    Stores non-destructive redaction coordinates so original content
    can be recovered with appropriate authorization.

    Table: lgl_redactions
    """

    __tablename__ = "lgl_redactions"

    document_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ediscovery_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    entity_counts: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    span_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    original_length: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    redacted_length: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    spans: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    redaction_method: Mapped[str] = mapped_column(
        String(30), nullable=False, default="presidio"
    )  # presidio | pattern_fallback
    is_reversible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class EDRMWorkflowRecord(AumOSModel):
    """EDRM workflow progress record for a litigation matter.

    Table: lgl_edrm_workflows
    """

    __tablename__ = "lgl_edrm_workflows"

    case_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    case_number: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    matter_type: Mapped[str] = mapped_column(String(100), nullable=False)
    current_stage: Mapped[str] = mapped_column(String(50), nullable=False, default="identification")
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="active"
    )  # active | completed | suspended
    stages_completed: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    total_documents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    produced_documents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    workflow_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class JurisdictionRuleRecord(AumOSModel):
    """Multi-jurisdictional privilege rule record.

    Table: lgl_jurisdiction_rules
    """

    __tablename__ = "lgl_jurisdiction_rules"

    jurisdiction_code: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    rule_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # attorney_client | work_product | common_interest | mediation
    description: Mapped[str] = mapped_column(Text, nullable=False)
    effective_date: Mapped[datetime] = mapped_column(Date, nullable=False)
    supersedes_rule_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    citation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    rule_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class CaseCitationRecord(AumOSModel):
    """Case law citation retrieved from CourtListener or other sources.

    Table: lgl_case_citations
    """

    __tablename__ = "lgl_case_citations"

    case_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    case_name: Mapped[str] = mapped_column(String(512), nullable=False)
    citation: Mapped[str] = mapped_column(String(255), nullable=False)
    court: Mapped[str] = mapped_column(String(100), nullable=False)
    jurisdiction: Mapped[str] = mapped_column(String(50), nullable=False)
    decision_date: Mapped[str | None] = mapped_column(String(20), nullable=True)
    docket_number: Mapped[str | None] = mapped_column(String(100), nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    url: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    source: Mapped[str] = mapped_column(String(50), nullable=False, default="courtlistener")
    search_query: Mapped[str | None] = mapped_column(String(512), nullable=True)


__all__ = [
    "PrivilegeCheck",
    "EDiscoveryJob",
    "AuditTrail",
    "PrivilegeLog",
    "LegalHold",
    "TARProject",
    "TARBatch",
    "TARDocumentReview",
    "LGLProductionSet",
    "LGLProductionDocument",
    "EDiscoveryRedaction",
    "EDRMWorkflowRecord",
    "JurisdictionRuleRecord",
    "CaseCitationRecord",
]
