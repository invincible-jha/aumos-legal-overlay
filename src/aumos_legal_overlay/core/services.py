"""Business logic services for aumos-legal-overlay.

Services contain all domain logic. They:
  - Accept dependencies via constructor injection (repositories, publishers)
  - Orchestrate repository calls and event publishing
  - Raise domain errors using aumos_common.errors
  - Are framework-agnostic (no FastAPI, no direct DB access)

After any state-changing operation, publish a Kafka event via EventPublisher.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone

from aumos_common.auth import TenantContext
from aumos_common.errors import NotFoundError, ValidationError
from aumos_common.observability import get_logger

from aumos_legal_overlay.adapters.kafka import LegalDomainEventPublisher
from aumos_legal_overlay.core.interfaces import (
    IAuditTrailRepository,
    IEDiscoveryJobRepository,
    ILegalHoldRepository,
    IPrivilegeCheckRepository,
    IPrivilegeLogRepository,
)
from aumos_legal_overlay.core.models import (
    AuditTrail,
    EDiscoveryJob,
    LegalHold,
    PrivilegeCheck,
    PrivilegeLog,
)

logger = get_logger(__name__)


class PrivilegeService:
    """Manages attorney-client privilege preservation checks for synthetic data.

    Analyzes documents to determine privilege status, records review outcomes,
    and maintains the chain of custody for privileged document handling.

    Args:
        repository: Data access layer implementing IPrivilegeCheckRepository.
        event_publisher: Publisher for privilege domain events.
        confidence_threshold: Minimum confidence score to flag as privileged.
    """

    def __init__(
        self,
        repository: IPrivilegeCheckRepository,
        event_publisher: LegalDomainEventPublisher,
        confidence_threshold: float = 0.85,
    ) -> None:
        """Initialize service with injected dependencies.

        Args:
            repository: Repository implementing IPrivilegeCheckRepository.
            event_publisher: Domain event publisher for privilege events.
            confidence_threshold: Score above which a document is flagged privileged.
        """
        self._repository = repository
        self._event_publisher = event_publisher
        self._confidence_threshold = confidence_threshold

    async def check_privilege(
        self,
        document_id: str,
        document_type: str,
        privilege_type: str,
        confidence_score: float,
        metadata: dict,
        tenant: TenantContext,
        privilege_basis: str | None = None,
        reviewing_attorney: str | None = None,
    ) -> PrivilegeCheck:
        """Perform a privilege preservation check for a document.

        Evaluates whether a document contains privileged content based on
        the confidence score and threshold. Creates an audit record for
        every privilege determination.

        Args:
            document_id: Unique identifier of the document being checked.
            document_type: Type of document (email, memo, contract, etc.).
            privilege_type: Type of privilege claimed (attorney_client, work_product).
            confidence_score: ML-derived confidence score between 0.0 and 1.0.
            metadata: Additional document metadata for audit purposes.
            tenant: Tenant context for RLS isolation.
            privilege_basis: Legal basis for the privilege claim.
            reviewing_attorney: Name of the reviewing attorney if applicable.

        Returns:
            The created PrivilegeCheck record.

        Raises:
            ValidationError: If confidence_score is outside [0.0, 1.0].
        """
        if not 0.0 <= confidence_score <= 1.0:
            raise ValidationError("confidence_score must be between 0.0 and 1.0")

        is_privileged = confidence_score >= self._confidence_threshold

        logger.info(
            "Performing privilege check",
            document_id=document_id,
            privilege_type=privilege_type,
            confidence_score=confidence_score,
            is_privileged=is_privileged,
            tenant_id=str(tenant.tenant_id),
        )

        check = await self._repository.create(
            document_id=document_id,
            document_type=document_type,
            privilege_type=privilege_type,
            is_privileged=is_privileged,
            confidence_score=confidence_score,
            metadata=metadata,
            tenant=tenant,
            privilege_basis=privilege_basis,
            reviewing_attorney=reviewing_attorney,
        )

        await self._event_publisher.publish_privilege_checked(
            tenant_id=tenant.tenant_id,
            check_id=check.id,
            document_id=document_id,
            is_privileged=is_privileged,
            correlation_id=str(uuid.uuid4()),
        )

        return check

    async def get_privilege_status(
        self, check_id: uuid.UUID, tenant: TenantContext
    ) -> PrivilegeCheck:
        """Retrieve the privilege status for a specific check.

        Args:
            check_id: UUID of the privilege check to retrieve.
            tenant: Tenant context for RLS isolation.

        Returns:
            The PrivilegeCheck record.

        Raises:
            NotFoundError: If no check exists with the given ID.
        """
        check = await self._repository.get_by_id(check_id, tenant)
        if check is None:
            raise NotFoundError(f"Privilege check {check_id} not found")
        return check


class EDiscoveryService:
    """Manages e-discovery synthetic data generation jobs.

    Coordinates the creation and tracking of e-discovery data generation
    requests, including document sets, custodians, and date ranges for
    litigation support.

    Args:
        repository: Data access layer implementing IEDiscoveryJobRepository.
        event_publisher: Publisher for e-discovery domain events.
    """

    def __init__(
        self,
        repository: IEDiscoveryJobRepository,
        event_publisher: LegalDomainEventPublisher,
    ) -> None:
        """Initialize service with injected dependencies.

        Args:
            repository: Repository implementing IEDiscoveryJobRepository.
            event_publisher: Domain event publisher for e-discovery events.
        """
        self._repository = repository
        self._event_publisher = event_publisher

    async def generate_ediscovery_data(
        self,
        case_name: str,
        custodians: list[str],
        document_types: list[str],
        document_count_requested: int,
        tenant: TenantContext,
        case_number: str | None = None,
        date_range_start: datetime | None = None,
        date_range_end: datetime | None = None,
        job_metadata: dict | None = None,
    ) -> EDiscoveryJob:
        """Create an e-discovery data generation job.

        Queues a new job to generate synthetic e-discovery data for the
        specified case parameters. Document generation occurs asynchronously.

        Args:
            case_name: Human-readable name of the legal case.
            custodians: List of custodians whose data should be generated.
            document_types: Types of documents to generate (email, memo, etc.).
            document_count_requested: Total number of synthetic documents to create.
            tenant: Tenant context for RLS isolation.
            case_number: Official court case number if available.
            date_range_start: Start of the relevant date range for documents.
            date_range_end: End of the relevant date range for documents.
            job_metadata: Additional job configuration parameters.

        Returns:
            The created EDiscoveryJob record with queued status.

        Raises:
            ValidationError: If document_count_requested is non-positive.
        """
        if document_count_requested <= 0:
            raise ValidationError("document_count_requested must be a positive integer")
        if not custodians:
            raise ValidationError("At least one custodian is required")

        logger.info(
            "Creating e-discovery job",
            case_name=case_name,
            case_number=case_number,
            document_count=document_count_requested,
            custodian_count=len(custodians),
            tenant_id=str(tenant.tenant_id),
        )

        job = await self._repository.create(
            case_name=case_name,
            custodians=custodians,
            document_types=document_types,
            document_count_requested=document_count_requested,
            tenant=tenant,
            case_number=case_number,
            date_range_start=date_range_start,
            date_range_end=date_range_end,
            job_metadata=job_metadata or {},
        )

        await self._event_publisher.publish_ediscovery_job_created(
            tenant_id=tenant.tenant_id,
            job_id=job.id,
            case_name=case_name,
            correlation_id=str(uuid.uuid4()),
        )

        return job

    async def get_job_status(
        self, job_id: uuid.UUID, tenant: TenantContext
    ) -> EDiscoveryJob:
        """Retrieve the status of an e-discovery generation job.

        Args:
            job_id: UUID of the e-discovery job to retrieve.
            tenant: Tenant context for RLS isolation.

        Returns:
            The EDiscoveryJob record with current status.

        Raises:
            NotFoundError: If no job exists with the given ID.
        """
        job = await self._repository.get_by_id(job_id, tenant)
        if job is None:
            raise NotFoundError(f"E-discovery job {job_id} not found")
        return job


class AuditTrailService:
    """Manages court-admissible audit trail entries.

    Records every significant system action with cryptographic integrity
    using a hash-chained linked list to prevent tampering. Each entry
    references the hash of the previous entry for chain-of-custody validation.

    Args:
        repository: Data access layer implementing IAuditTrailRepository.
        event_publisher: Publisher for audit domain events.
        hash_algorithm: Hashing algorithm for integrity verification.
    """

    def __init__(
        self,
        repository: IAuditTrailRepository,
        event_publisher: LegalDomainEventPublisher,
        hash_algorithm: str = "sha256",
    ) -> None:
        """Initialize service with injected dependencies.

        Args:
            repository: Repository implementing IAuditTrailRepository.
            event_publisher: Domain event publisher for audit events.
            hash_algorithm: Algorithm to use for integrity hashing (default: sha256).
        """
        self._repository = repository
        self._event_publisher = event_publisher
        self._hash_algorithm = hash_algorithm

    def _compute_integrity_hash(
        self,
        action: str,
        actor_id: str,
        resource_type: str,
        resource_id: str,
        action_timestamp: datetime,
        action_detail: dict,
        previous_hash: str | None,
        tenant_id: uuid.UUID,
    ) -> str:
        """Compute a deterministic integrity hash for an audit entry.

        Chains the previous hash to form a tamper-evident linked list.

        Args:
            action: The action being recorded.
            actor_id: Identifier of the actor performing the action.
            resource_type: Type of resource being acted upon.
            resource_id: Identifier of the resource.
            action_timestamp: When the action occurred.
            action_detail: Structured detail of the action.
            previous_hash: Hash of the immediately preceding audit entry.
            tenant_id: The tenant this entry belongs to.

        Returns:
            Hex-encoded hash string.
        """
        payload = {
            "action": action,
            "actor_id": actor_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "action_timestamp": action_timestamp.isoformat(),
            "action_detail": action_detail,
            "previous_hash": previous_hash,
            "tenant_id": str(tenant_id),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.new(self._hash_algorithm, canonical.encode()).hexdigest()

    async def record_action(
        self,
        action: str,
        actor_id: str,
        actor_type: str,
        resource_type: str,
        resource_id: str,
        action_detail: dict,
        tenant: TenantContext,
        ip_address: str | None = None,
        user_agent: str | None = None,
        legal_hold_id: uuid.UUID | None = None,
    ) -> AuditTrail:
        """Record a court-admissible audit trail entry.

        Creates a hash-chained audit entry linking to the previous entry
        for tamper-evident chain-of-custody documentation.

        Args:
            action: The action being audited (e.g., document_accessed, privilege_checked).
            actor_id: ID of the user or system performing the action.
            actor_type: Type of actor (user, system, attorney, admin).
            resource_type: Type of resource being acted upon.
            resource_id: ID of the resource being acted upon.
            action_detail: Structured detail about what happened.
            tenant: Tenant context for RLS isolation.
            ip_address: IP address of the actor if available.
            user_agent: User agent string if available.
            legal_hold_id: Associated legal hold UUID if applicable.

        Returns:
            The created AuditTrail entry with integrity hash.
        """
        action_timestamp = datetime.now(tz=timezone.utc)
        previous_hash = await self._repository.get_latest_hash(tenant)

        integrity_hash = self._compute_integrity_hash(
            action=action,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action_timestamp=action_timestamp,
            action_detail=action_detail,
            previous_hash=previous_hash,
            tenant_id=tenant.tenant_id,
        )

        logger.info(
            "Recording audit trail entry",
            action=action,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            tenant_id=str(tenant.tenant_id),
        )

        entry = await self._repository.create(
            action=action,
            actor_id=actor_id,
            actor_type=actor_type,
            resource_type=resource_type,
            resource_id=resource_id,
            action_timestamp=action_timestamp,
            action_detail=action_detail,
            integrity_hash=integrity_hash,
            tenant=tenant,
            ip_address=ip_address,
            user_agent=user_agent,
            previous_hash=previous_hash,
            legal_hold_id=legal_hold_id,
        )

        return entry

    async def export_audit_trail(
        self,
        start_time: datetime,
        end_time: datetime,
        tenant: TenantContext,
        resource_type: str | None = None,
    ) -> list[AuditTrail]:
        """Export audit trail entries for a time range.

        Retrieves all audit entries within the specified window,
        optionally filtered by resource type, for court submission.

        Args:
            start_time: Start of the export window (inclusive).
            end_time: End of the export window (inclusive).
            tenant: Tenant context for RLS isolation.
            resource_type: Optional filter to a specific resource type.

        Returns:
            Ordered list of AuditTrail entries suitable for court submission.

        Raises:
            ValidationError: If end_time is before start_time.
        """
        if end_time <= start_time:
            raise ValidationError("end_time must be after start_time")

        logger.info(
            "Exporting audit trail",
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            resource_type=resource_type,
            tenant_id=str(tenant.tenant_id),
        )

        return await self._repository.export_range(
            start_time=start_time,
            end_time=end_time,
            tenant=tenant,
            resource_type=resource_type,
        )


class PrivilegeLogService:
    """Manages automated privilege log entries for discovery responses.

    Generates and maintains privilege log entries compliant with
    Federal Rule of Civil Procedure 26(b)(5), tracking all documents
    withheld or redacted on privilege grounds.

    Args:
        repository: Data access layer implementing IPrivilegeLogRepository.
        event_publisher: Publisher for privilege log domain events.
    """

    def __init__(
        self,
        repository: IPrivilegeLogRepository,
        event_publisher: LegalDomainEventPublisher,
    ) -> None:
        """Initialize service with injected dependencies.

        Args:
            repository: Repository implementing IPrivilegeLogRepository.
            event_publisher: Domain event publisher for privilege log events.
        """
        self._repository = repository
        self._event_publisher = event_publisher

    async def create_log_entry(
        self,
        document_id: str,
        document_type: str,
        privilege_claimed: str,
        privilege_description: str,
        subject_matter: str,
        basis_for_claim: str,
        tenant: TenantContext,
        document_date: datetime | None = None,
        author: str | None = None,
        recipients: list[str] | None = None,
        privilege_check_id: uuid.UUID | None = None,
        case_number: str | None = None,
        is_redacted: bool = False,
    ) -> PrivilegeLog:
        """Create a privilege log entry for a withheld or redacted document.

        Automatically assigns a sequential log entry number per case for
        compliance with discovery response formatting requirements.

        Args:
            document_id: Identifier of the privileged document.
            document_type: Type of document (email, memo, attachment, etc.).
            privilege_claimed: Type of privilege (attorney_client, work_product).
            privilege_description: Description of the privilege being claimed.
            subject_matter: Subject matter of the document.
            basis_for_claim: Legal basis for the privilege claim.
            tenant: Tenant context for RLS isolation.
            document_date: Date of the document if known.
            author: Author of the document if known.
            recipients: List of recipients if applicable.
            privilege_check_id: Link to the PrivilegeCheck that identified privilege.
            case_number: Case number for sequential numbering within a case.
            is_redacted: Whether the document is redacted rather than fully withheld.

        Returns:
            The created PrivilegeLog entry with assigned entry number.
        """
        next_number = await self._repository.get_next_entry_number(
            case_number or "default", tenant
        )

        logger.info(
            "Creating privilege log entry",
            document_id=document_id,
            privilege_claimed=privilege_claimed,
            log_entry_number=next_number,
            case_number=case_number,
            tenant_id=str(tenant.tenant_id),
        )

        entry = await self._repository.create(
            document_id=document_id,
            document_type=document_type,
            privilege_claimed=privilege_claimed,
            privilege_description=privilege_description,
            subject_matter=subject_matter,
            basis_for_claim=basis_for_claim,
            log_entry_number=next_number,
            tenant=tenant,
            document_date=document_date,
            author=author,
            recipients=recipients or [],
            privilege_check_id=privilege_check_id,
            case_number=case_number,
            is_redacted=is_redacted,
        )

        await self._event_publisher.publish_privilege_log_entry_created(
            tenant_id=tenant.tenant_id,
            entry_id=entry.id,
            document_id=document_id,
            correlation_id=str(uuid.uuid4()),
        )

        return entry

    async def get_privilege_log(
        self, tenant: TenantContext, case_number: str | None = None
    ) -> list[PrivilegeLog]:
        """Retrieve the full privilege log, optionally filtered by case.

        Args:
            tenant: Tenant context for RLS isolation.
            case_number: Optional case number to filter entries.

        Returns:
            Ordered list of PrivilegeLog entries for discovery response.
        """
        if case_number:
            return await self._repository.list_by_case(case_number, tenant)
        return await self._repository.list_all(tenant)


class LegalHoldService:
    """Manages legal hold creation, custodian tracking, and compliance.

    Handles the full lifecycle of legal holds including issuance,
    custodian notification, acknowledgement tracking, and release,
    ensuring preservation obligations are met for litigation readiness.

    Args:
        repository: Data access layer implementing ILegalHoldRepository.
        event_publisher: Publisher for legal hold domain events.
    """

    def __init__(
        self,
        repository: ILegalHoldRepository,
        event_publisher: LegalDomainEventPublisher,
    ) -> None:
        """Initialize service with injected dependencies.

        Args:
            repository: Repository implementing ILegalHoldRepository.
            event_publisher: Domain event publisher for legal hold events.
        """
        self._repository = repository
        self._event_publisher = event_publisher

    async def create_legal_hold(
        self,
        hold_name: str,
        case_name: str,
        matter_type: str,
        issuing_attorney: str,
        custodians: list[str],
        data_sources: list[str],
        tenant: TenantContext,
        case_number: str | None = None,
        hold_expires_at: datetime | None = None,
        hold_metadata: dict | None = None,
    ) -> LegalHold:
        """Create and issue a new legal hold.

        Issues a preservation hold covering the specified custodians and
        data sources. Publishes a notification event for downstream
        custodian notification workflows.

        Args:
            hold_name: Descriptive name for the legal hold.
            case_name: Name of the associated legal matter.
            matter_type: Type of matter (litigation, investigation, etc.).
            issuing_attorney: Name of the attorney issuing the hold.
            custodians: List of custodians subject to the hold.
            data_sources: List of data sources to be preserved.
            tenant: Tenant context for RLS isolation.
            case_number: Official case number if available.
            hold_expires_at: Optional expiration date for the hold.
            hold_metadata: Additional hold configuration metadata.

        Returns:
            The created LegalHold record with active status.

        Raises:
            ValidationError: If custodians or data_sources are empty.
        """
        if not custodians:
            raise ValidationError("At least one custodian is required for a legal hold")
        if not data_sources:
            raise ValidationError("At least one data source must be specified")

        hold_issued_at = datetime.now(tz=timezone.utc)

        logger.info(
            "Creating legal hold",
            hold_name=hold_name,
            case_name=case_name,
            matter_type=matter_type,
            custodian_count=len(custodians),
            tenant_id=str(tenant.tenant_id),
        )

        hold = await self._repository.create(
            hold_name=hold_name,
            case_name=case_name,
            matter_type=matter_type,
            issuing_attorney=issuing_attorney,
            custodians=custodians,
            data_sources=data_sources,
            hold_issued_at=hold_issued_at,
            tenant=tenant,
            case_number=case_number,
            hold_expires_at=hold_expires_at,
            hold_metadata=hold_metadata or {},
        )

        await self._event_publisher.publish_legal_hold_created(
            tenant_id=tenant.tenant_id,
            hold_id=hold.id,
            hold_name=hold_name,
            custodians=custodians,
            correlation_id=str(uuid.uuid4()),
        )

        return hold

    async def get_hold_status(
        self, hold_id: uuid.UUID, tenant: TenantContext
    ) -> LegalHold:
        """Retrieve the current status of a legal hold.

        Args:
            hold_id: UUID of the legal hold to retrieve.
            tenant: Tenant context for RLS isolation.

        Returns:
            The LegalHold record with current status and custodian acknowledgements.

        Raises:
            NotFoundError: If no hold exists with the given ID.
        """
        hold = await self._repository.get_by_id(hold_id, tenant)
        if hold is None:
            raise NotFoundError(f"Legal hold {hold_id} not found")
        return hold

    async def release_hold(
        self,
        hold_id: uuid.UUID,
        release_reason: str,
        tenant: TenantContext,
    ) -> LegalHold:
        """Release an active legal hold.

        Args:
            hold_id: UUID of the legal hold to release.
            release_reason: Documented reason for releasing the hold.
            tenant: Tenant context for RLS isolation.

        Returns:
            The updated LegalHold record with released status.

        Raises:
            NotFoundError: If no hold exists with the given ID.
            ValidationError: If the hold is not currently active.
        """
        hold = await self._repository.get_by_id(hold_id, tenant)
        if hold is None:
            raise NotFoundError(f"Legal hold {hold_id} not found")
        if hold.status != "active":
            raise ValidationError(f"Cannot release hold with status '{hold.status}'")

        updated = await self._repository.update_status(
            hold_id=hold_id,
            status="released",
            tenant=tenant,
            release_reason=release_reason,
        )

        await self._event_publisher.publish_legal_hold_released(
            tenant_id=tenant.tenant_id,
            hold_id=hold_id,
            release_reason=release_reason,
            correlation_id=str(uuid.uuid4()),
        )

        logger.info(
            "Legal hold released",
            hold_id=str(hold_id),
            release_reason=release_reason,
            tenant_id=str(tenant.tenant_id),
        )

        return updated  # type: ignore[return-value]
