"""Pydantic request and response schemas for aumos-legal-overlay API.

All API inputs and outputs use Pydantic models — never raw dicts.
Schemas are grouped by resource following the naming convention:
  {Resource}Request  — POST body
  {Resource}Response — GET/POST response
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Privilege Check Schemas
# ---------------------------------------------------------------------------


class PrivilegeCheckRequest(BaseModel):
    """Request body for POST /api/v1/legal/privilege/check."""

    document_id: str = Field(description="Unique identifier of the document to check")
    document_type: str = Field(description="Type of document (email, memo, contract, etc.)")
    privilege_type: str = Field(
        description="Type of privilege to check (attorney_client, work_product, common_interest)"
    )
    confidence_score: float = Field(
        ge=0.0, le=1.0, description="ML-derived confidence score between 0.0 and 1.0"
    )
    metadata: dict = Field(default_factory=dict, description="Additional document metadata")
    privilege_basis: str | None = Field(default=None, description="Legal basis for the privilege claim")
    reviewing_attorney: str | None = Field(default=None, description="Name of the reviewing attorney")


class PrivilegeCheckResponse(BaseModel):
    """Response schema for privilege check results."""

    id: uuid.UUID = Field(description="Unique identifier of the privilege check")
    tenant_id: uuid.UUID = Field(description="Owning tenant identifier")
    document_id: str = Field(description="Document that was checked")
    document_type: str = Field(description="Type of the document")
    privilege_type: str = Field(description="Type of privilege evaluated")
    is_privileged: bool = Field(description="Whether the document is determined privileged")
    confidence_score: float = Field(description="Confidence score of the privilege determination")
    privilege_basis: str | None = Field(description="Legal basis for the privilege claim")
    reviewing_attorney: str | None = Field(description="Reviewing attorney if applicable")
    review_timestamp: datetime | None = Field(description="When the review was completed")
    status: str = Field(description="Check status (pending, reviewed, appealed, final)")
    created_at: datetime = Field(description="When the check was created")
    updated_at: datetime = Field(description="When the check was last updated")


# ---------------------------------------------------------------------------
# E-Discovery Schemas
# ---------------------------------------------------------------------------


class EDiscoveryGenerateRequest(BaseModel):
    """Request body for POST /api/v1/legal/ediscovery/generate."""

    case_name: str = Field(description="Human-readable name of the legal case")
    case_number: str | None = Field(default=None, description="Official court case number")
    custodians: list[str] = Field(min_length=1, description="List of custodians whose data to generate")
    document_types: list[str] = Field(
        min_length=1, description="Types of documents to generate (email, memo, contract, etc.)"
    )
    document_count_requested: int = Field(gt=0, description="Total number of synthetic documents to create")
    date_range_start: datetime | None = Field(default=None, description="Start of the relevant date range")
    date_range_end: datetime | None = Field(default=None, description="End of the relevant date range")
    job_metadata: dict = Field(default_factory=dict, description="Additional job configuration parameters")


class EDiscoveryJobResponse(BaseModel):
    """Response schema for e-discovery job status."""

    id: uuid.UUID = Field(description="Unique job identifier")
    tenant_id: uuid.UUID = Field(description="Owning tenant identifier")
    case_name: str = Field(description="Name of the legal case")
    case_number: str | None = Field(description="Official court case number")
    custodians: list[str] = Field(description="Custodians in scope")
    document_types: list[str] = Field(description="Document types being generated")
    document_count_requested: int = Field(description="Number of documents requested")
    document_count_generated: int = Field(description="Number of documents generated so far")
    date_range_start: datetime | None = Field(description="Start of the date range")
    date_range_end: datetime | None = Field(description="End of the date range")
    status: str = Field(description="Job status (queued, processing, completed, failed)")
    output_location: str | None = Field(description="Storage location of generated documents")
    error_message: str | None = Field(description="Error details if job failed")
    created_at: datetime = Field(description="When the job was created")
    updated_at: datetime = Field(description="When the job was last updated")


# ---------------------------------------------------------------------------
# Audit Trail Schemas
# ---------------------------------------------------------------------------


class AuditTrailExportRequest(BaseModel):
    """Request body for POST /api/v1/legal/audit/export."""

    start_time: datetime = Field(description="Start of the export window (inclusive)")
    end_time: datetime = Field(description="End of the export window (inclusive)")
    resource_type: str | None = Field(default=None, description="Optional filter by resource type")


class AuditTrailEntryResponse(BaseModel):
    """Response schema for a single audit trail entry."""

    id: uuid.UUID = Field(description="Unique entry identifier")
    tenant_id: uuid.UUID = Field(description="Owning tenant identifier")
    action: str = Field(description="Action that was performed")
    actor_id: str = Field(description="Identifier of the actor")
    actor_type: str = Field(description="Type of actor (user, system, attorney, admin)")
    resource_type: str = Field(description="Type of resource acted upon")
    resource_id: str = Field(description="Identifier of the resource")
    action_timestamp: datetime = Field(description="When the action occurred")
    action_detail: dict = Field(description="Structured detail of the action")
    integrity_hash: str = Field(description="SHA-256 integrity hash for tamper detection")
    previous_hash: str | None = Field(description="Hash of the preceding entry for chain verification")
    is_immutable: bool = Field(description="Whether this entry is locked from modification")
    legal_hold_id: uuid.UUID | None = Field(description="Associated legal hold if applicable")
    created_at: datetime = Field(description="When the entry was recorded")


class AuditTrailExportResponse(BaseModel):
    """Response schema for audit trail export."""

    entries: list[AuditTrailEntryResponse] = Field(description="Audit trail entries in chronological order")
    total_count: int = Field(description="Total number of entries in the export")
    start_time: datetime = Field(description="Start of the exported window")
    end_time: datetime = Field(description="End of the exported window")
    export_hash: str = Field(description="Integrity hash of the full export for court submission")


# ---------------------------------------------------------------------------
# Privilege Log Schemas
# ---------------------------------------------------------------------------


class PrivilegeLogResponse(BaseModel):
    """Response schema for a single privilege log entry."""

    id: uuid.UUID = Field(description="Unique entry identifier")
    tenant_id: uuid.UUID = Field(description="Owning tenant identifier")
    log_entry_number: int = Field(description="Sequential entry number within the case")
    document_id: str = Field(description="Identifier of the privileged document")
    document_date: datetime | None = Field(description="Date of the document")
    document_type: str = Field(description="Type of document")
    author: str | None = Field(description="Author of the document")
    recipients: list[str] = Field(description="Document recipients")
    privilege_claimed: str = Field(description="Type of privilege claimed")
    privilege_description: str = Field(description="Description of the privilege")
    subject_matter: str = Field(description="Subject matter of the document")
    basis_for_claim: str = Field(description="Legal basis for the claim")
    case_number: str | None = Field(description="Associated case number")
    is_redacted: bool = Field(description="Whether document is redacted rather than withheld")
    created_at: datetime = Field(description="When the log entry was created")


class PrivilegeLogListResponse(BaseModel):
    """Response schema for listing privilege log entries."""

    entries: list[PrivilegeLogResponse] = Field(description="Privilege log entries")
    total_count: int = Field(description="Total number of entries")
    case_number: str | None = Field(description="Case number filter if applied")


# ---------------------------------------------------------------------------
# Legal Hold Schemas
# ---------------------------------------------------------------------------


class LegalHoldCreateRequest(BaseModel):
    """Request body for POST /api/v1/legal/hold."""

    hold_name: str = Field(description="Descriptive name for the legal hold")
    case_name: str = Field(description="Name of the associated legal matter")
    case_number: str | None = Field(default=None, description="Official case number")
    matter_type: str = Field(
        description="Type of matter (litigation, investigation, regulatory, arbitration)"
    )
    issuing_attorney: str = Field(description="Name of the attorney issuing the hold")
    custodians: list[str] = Field(min_length=1, description="Custodians subject to the hold")
    data_sources: list[str] = Field(min_length=1, description="Data sources to be preserved")
    hold_expires_at: datetime | None = Field(default=None, description="Optional expiration date")
    hold_metadata: dict = Field(default_factory=dict, description="Additional hold configuration")


class LegalHoldResponse(BaseModel):
    """Response schema for legal hold status."""

    id: uuid.UUID = Field(description="Unique hold identifier")
    tenant_id: uuid.UUID = Field(description="Owning tenant identifier")
    hold_name: str = Field(description="Hold name")
    case_name: str = Field(description="Associated case name")
    case_number: str | None = Field(description="Official case number")
    matter_type: str = Field(description="Type of legal matter")
    issuing_attorney: str = Field(description="Attorney who issued the hold")
    custodians: list[str] = Field(description="Custodians subject to the hold")
    custodian_acknowledgements: dict = Field(description="Per-custodian acknowledgement timestamps")
    data_sources: list[str] = Field(description="Data sources under preservation")
    hold_issued_at: datetime = Field(description="When the hold was issued")
    hold_expires_at: datetime | None = Field(description="When the hold expires")
    status: str = Field(description="Hold status (active, released, suspended, expired)")
    last_reminder_sent_at: datetime | None = Field(description="When the last reminder was sent")
    release_reason: str | None = Field(description="Reason for release if hold is released")
    created_at: datetime = Field(description="When the hold record was created")
    updated_at: datetime = Field(description="When the hold was last updated")
