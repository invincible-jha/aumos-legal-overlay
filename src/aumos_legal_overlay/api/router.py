"""API router for aumos-legal-overlay.

All endpoints are registered here and included in main.py under /api/v1/legal.
Routes delegate all logic to the service layer — no business logic in routes.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.auth import TenantContext, get_current_user
from aumos_common.database import get_db_session
from aumos_common.events import EventPublisher

from aumos_legal_overlay.adapters.kafka import LegalDomainEventPublisher
from aumos_legal_overlay.adapters.repositories import (
    AuditTrailRepository,
    EDiscoveryJobRepository,
    LegalHoldRepository,
    PrivilegeCheckRepository,
    PrivilegeLogRepository,
)
from aumos_legal_overlay.api.schemas import (
    AuditTrailExportRequest,
    AuditTrailExportResponse,
    AuditTrailEntryResponse,
    EDiscoveryGenerateRequest,
    EDiscoveryJobResponse,
    LegalHoldCreateRequest,
    LegalHoldResponse,
    PrivilegeCheckRequest,
    PrivilegeCheckResponse,
    PrivilegeLogListResponse,
    PrivilegeLogResponse,
)
from aumos_legal_overlay.core.services import (
    AuditTrailService,
    EDiscoveryService,
    LegalHoldService,
    PrivilegeLogService,
    PrivilegeService,
)

router = APIRouter(prefix="/legal", tags=["legal"])


# ---------------------------------------------------------------------------
# Dependency factories
# ---------------------------------------------------------------------------


def get_event_publisher() -> LegalDomainEventPublisher:
    """Provide a configured LegalDomainEventPublisher.

    Returns:
        LegalDomainEventPublisher instance using the shared EventPublisher.
    """
    return LegalDomainEventPublisher(publisher=EventPublisher())


def get_privilege_service(
    session: AsyncSession = Depends(get_db_session),
    event_publisher: LegalDomainEventPublisher = Depends(get_event_publisher),
) -> PrivilegeService:
    """Provide a configured PrivilegeService.

    Args:
        session: Injected async database session.
        event_publisher: Injected event publisher.

    Returns:
        PrivilegeService with all dependencies wired.
    """
    return PrivilegeService(
        repository=PrivilegeCheckRepository(session),
        event_publisher=event_publisher,
    )


def get_ediscovery_service(
    session: AsyncSession = Depends(get_db_session),
    event_publisher: LegalDomainEventPublisher = Depends(get_event_publisher),
) -> EDiscoveryService:
    """Provide a configured EDiscoveryService.

    Args:
        session: Injected async database session.
        event_publisher: Injected event publisher.

    Returns:
        EDiscoveryService with all dependencies wired.
    """
    return EDiscoveryService(
        repository=EDiscoveryJobRepository(session),
        event_publisher=event_publisher,
    )


def get_audit_trail_service(
    session: AsyncSession = Depends(get_db_session),
    event_publisher: LegalDomainEventPublisher = Depends(get_event_publisher),
) -> AuditTrailService:
    """Provide a configured AuditTrailService.

    Args:
        session: Injected async database session.
        event_publisher: Injected event publisher.

    Returns:
        AuditTrailService with all dependencies wired.
    """
    return AuditTrailService(
        repository=AuditTrailRepository(session),
        event_publisher=event_publisher,
    )


def get_privilege_log_service(
    session: AsyncSession = Depends(get_db_session),
    event_publisher: LegalDomainEventPublisher = Depends(get_event_publisher),
) -> PrivilegeLogService:
    """Provide a configured PrivilegeLogService.

    Args:
        session: Injected async database session.
        event_publisher: Injected event publisher.

    Returns:
        PrivilegeLogService with all dependencies wired.
    """
    return PrivilegeLogService(
        repository=PrivilegeLogRepository(session),
        event_publisher=event_publisher,
    )


def get_legal_hold_service(
    session: AsyncSession = Depends(get_db_session),
    event_publisher: LegalDomainEventPublisher = Depends(get_event_publisher),
) -> LegalHoldService:
    """Provide a configured LegalHoldService.

    Args:
        session: Injected async database session.
        event_publisher: Injected event publisher.

    Returns:
        LegalHoldService with all dependencies wired.
    """
    return LegalHoldService(
        repository=LegalHoldRepository(session),
        event_publisher=event_publisher,
    )


# ---------------------------------------------------------------------------
# Privilege endpoints
# ---------------------------------------------------------------------------


@router.post("/privilege/check", response_model=PrivilegeCheckResponse, status_code=201)
async def check_privilege_preservation(
    request: PrivilegeCheckRequest,
    tenant: TenantContext = Depends(get_current_user),
    service: PrivilegeService = Depends(get_privilege_service),
) -> PrivilegeCheckResponse:
    """Check attorney-client privilege preservation for a document.

    Analyzes the document against privilege thresholds and records
    the determination. Returns the full privilege check record.
    """
    check = await service.check_privilege(
        document_id=request.document_id,
        document_type=request.document_type,
        privilege_type=request.privilege_type,
        confidence_score=request.confidence_score,
        metadata=request.metadata,
        tenant=tenant,
        privilege_basis=request.privilege_basis,
        reviewing_attorney=request.reviewing_attorney,
    )
    return PrivilegeCheckResponse.model_validate(check, from_attributes=True)


@router.get("/privilege/status/{check_id}", response_model=PrivilegeCheckResponse)
async def get_privilege_status(
    check_id: uuid.UUID,
    tenant: TenantContext = Depends(get_current_user),
    service: PrivilegeService = Depends(get_privilege_service),
) -> PrivilegeCheckResponse:
    """Retrieve the privilege status for a specific check.

    Returns the full privilege determination record including review status.
    """
    check = await service.get_privilege_status(check_id, tenant)
    return PrivilegeCheckResponse.model_validate(check, from_attributes=True)


# ---------------------------------------------------------------------------
# E-Discovery endpoints
# ---------------------------------------------------------------------------


@router.post("/ediscovery/generate", response_model=EDiscoveryJobResponse, status_code=202)
async def generate_ediscovery_data(
    request: EDiscoveryGenerateRequest,
    tenant: TenantContext = Depends(get_current_user),
    service: EDiscoveryService = Depends(get_ediscovery_service),
) -> EDiscoveryJobResponse:
    """Queue an e-discovery synthetic data generation job.

    Creates a background job to generate synthetic e-discovery documents
    for the specified case parameters. Returns immediately with job status.
    """
    job = await service.generate_ediscovery_data(
        case_name=request.case_name,
        custodians=request.custodians,
        document_types=request.document_types,
        document_count_requested=request.document_count_requested,
        tenant=tenant,
        case_number=request.case_number,
        date_range_start=request.date_range_start,
        date_range_end=request.date_range_end,
        job_metadata=request.job_metadata,
    )
    return EDiscoveryJobResponse.model_validate(job, from_attributes=True)


@router.get("/ediscovery/jobs/{job_id}", response_model=EDiscoveryJobResponse)
async def get_ediscovery_job_status(
    job_id: uuid.UUID,
    tenant: TenantContext = Depends(get_current_user),
    service: EDiscoveryService = Depends(get_ediscovery_service),
) -> EDiscoveryJobResponse:
    """Retrieve the status of an e-discovery generation job.

    Returns current job status, progress counts, and output location
    once generation is complete.
    """
    job = await service.get_job_status(job_id, tenant)
    return EDiscoveryJobResponse.model_validate(job, from_attributes=True)


# ---------------------------------------------------------------------------
# Audit trail endpoints
# ---------------------------------------------------------------------------


@router.post("/audit/export", response_model=AuditTrailExportResponse)
async def export_audit_trail(
    request: AuditTrailExportRequest,
    tenant: TenantContext = Depends(get_current_user),
    service: AuditTrailService = Depends(get_audit_trail_service),
) -> AuditTrailExportResponse:
    """Export a court-admissible audit trail for a time range.

    Returns all audit entries within the specified window, ordered
    chronologically. Includes an export-level integrity hash for
    court submission verification.
    """
    entries = await service.export_audit_trail(
        start_time=request.start_time,
        end_time=request.end_time,
        tenant=tenant,
        resource_type=request.resource_type,
    )

    entry_responses = [
        AuditTrailEntryResponse.model_validate(e, from_attributes=True) for e in entries
    ]

    # Compute an export-level integrity hash over all entry hashes
    entry_hashes = [e.integrity_hash for e in entry_responses]
    export_hash = hashlib.sha256(
        json.dumps(entry_hashes, separators=(",", ":")).encode()
    ).hexdigest()

    return AuditTrailExportResponse(
        entries=entry_responses,
        total_count=len(entry_responses),
        start_time=request.start_time,
        end_time=request.end_time,
        export_hash=export_hash,
    )


# ---------------------------------------------------------------------------
# Privilege log endpoints
# ---------------------------------------------------------------------------


@router.get("/privilege-log", response_model=PrivilegeLogListResponse)
async def get_privilege_log(
    case_number: str | None = Query(default=None, description="Filter by case number"),
    tenant: TenantContext = Depends(get_current_user),
    service: PrivilegeLogService = Depends(get_privilege_log_service),
) -> PrivilegeLogListResponse:
    """Retrieve the privilege log, optionally filtered by case number.

    Returns all privilege log entries formatted for discovery responses,
    compliant with Federal Rule of Civil Procedure 26(b)(5).
    """
    entries = await service.get_privilege_log(tenant, case_number=case_number)
    entry_responses = [
        PrivilegeLogResponse.model_validate(e, from_attributes=True) for e in entries
    ]
    return PrivilegeLogListResponse(
        entries=entry_responses,
        total_count=len(entry_responses),
        case_number=case_number,
    )


# ---------------------------------------------------------------------------
# Legal hold endpoints
# ---------------------------------------------------------------------------


@router.post("/hold", response_model=LegalHoldResponse, status_code=201)
async def create_legal_hold(
    request: LegalHoldCreateRequest,
    tenant: TenantContext = Depends(get_current_user),
    service: LegalHoldService = Depends(get_legal_hold_service),
) -> LegalHoldResponse:
    """Create and issue a new legal hold.

    Issues a preservation hold covering the specified custodians and
    data sources. Triggers custodian notification via Kafka event.
    """
    hold = await service.create_legal_hold(
        hold_name=request.hold_name,
        case_name=request.case_name,
        matter_type=request.matter_type,
        issuing_attorney=request.issuing_attorney,
        custodians=request.custodians,
        data_sources=request.data_sources,
        tenant=tenant,
        case_number=request.case_number,
        hold_expires_at=request.hold_expires_at,
        hold_metadata=request.hold_metadata,
    )
    return LegalHoldResponse.model_validate(hold, from_attributes=True)


@router.get("/hold/{hold_id}", response_model=LegalHoldResponse)
async def get_legal_hold_status(
    hold_id: uuid.UUID,
    tenant: TenantContext = Depends(get_current_user),
    service: LegalHoldService = Depends(get_legal_hold_service),
) -> LegalHoldResponse:
    """Retrieve the current status of a legal hold.

    Returns hold details including custodian acknowledgement status
    and preservation scope.
    """
    hold = await service.get_hold_status(hold_id, tenant)
    return LegalHoldResponse.model_validate(hold, from_attributes=True)
