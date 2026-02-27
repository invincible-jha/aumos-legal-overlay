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

from aumos_legal_overlay.adapters.clause_validator import ClauseValidator
from aumos_legal_overlay.adapters.contract_synthesizer import ContractSynthesizer
from aumos_legal_overlay.adapters.ip_protector import IPProtector
from aumos_legal_overlay.adapters.kafka import LegalDomainEventPublisher
from aumos_legal_overlay.adapters.legal_hold_manager import LegalHoldManager
from aumos_legal_overlay.adapters.liability_assessor import LiabilityAssessor
from aumos_legal_overlay.adapters.litigation_support import LitigationSupport
from aumos_legal_overlay.adapters.privilege_preserver import PrivilegePreserver
from aumos_legal_overlay.adapters.regulatory_monitor import RegulatoryMonitor
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


# ---------------------------------------------------------------------------
# New services wiring Phase 5 legal overlay adapters
# ---------------------------------------------------------------------------


class ContractSynthesisService:
    """Generates synthetic legal contracts for AI training and analysis.

    Wraps the ContractSynthesizer adapter, publishes events on contract
    generation, and logs batch synthesis operations.

    Args:
        synthesizer: ContractSynthesizer adapter instance.
        event_publisher: Domain event publisher for legal events.
    """

    def __init__(
        self,
        synthesizer: ContractSynthesizer,
        event_publisher: LegalDomainEventPublisher,
    ) -> None:
        """Initialize contract synthesis service.

        Args:
            synthesizer: ContractSynthesizer adapter.
            event_publisher: Domain event publisher.
        """
        self._synthesizer = synthesizer
        self._event_publisher = event_publisher

    async def synthesize_contract(
        self,
        contract_type: str,
        jurisdiction: str,
        complexity: str,
        party_count: int,
        tenant: TenantContext,
        metadata: dict | None = None,
    ) -> dict:
        """Synthesize a single legal contract and publish an event.

        Args:
            contract_type: Contract type identifier (NDA, MSA, SLA, etc.).
            jurisdiction: Legal jurisdiction for language adaptation.
            complexity: Clause complexity level (simple, standard, complex).
            party_count: Number of contract parties.
            tenant: Tenant context for RLS isolation.
            metadata: Optional metadata dict.

        Returns:
            Contract dict with contract_id, assembled_text, and metadata.
        """
        logger.info(
            "Synthesizing contract",
            contract_type=contract_type,
            jurisdiction=jurisdiction,
            complexity=complexity,
            tenant_id=str(tenant.tenant_id),
        )
        contract = await self._synthesizer.synthesize_contract(
            contract_type=contract_type,
            jurisdiction=jurisdiction,
            complexity=complexity,
            party_count=party_count,
            metadata=metadata,
        )
        await self._event_publisher.publish(
            topic="legal.contract.synthesized",
            payload={
                "tenant_id": str(tenant.tenant_id),
                "contract_id": contract["contract_id"],
                "contract_type": contract_type,
                "jurisdiction": jurisdiction,
                "word_count": contract.get("word_count", 0),
            },
        )
        return contract

    async def synthesize_batch(
        self,
        count: int,
        contract_types: list[str] | None,
        tenant: TenantContext,
    ) -> list[dict]:
        """Generate a batch of synthetic contracts.

        Args:
            count: Number of contracts to generate.
            contract_types: Optional list of contract types to draw from.
            tenant: Tenant context for RLS isolation.

        Returns:
            List of contract dicts.
        """
        logger.info(
            "Synthesizing contract batch",
            count=count,
            tenant_id=str(tenant.tenant_id),
        )
        contracts = await self._synthesizer.generate_batch(
            count=count,
            contract_types=contract_types,
        )
        await self._event_publisher.publish(
            topic="legal.contract.batch_synthesized",
            payload={
                "tenant_id": str(tenant.tenant_id),
                "count": len(contracts),
            },
        )
        return contracts


class ClauseValidationService:
    """Validates contract clauses for regulatory compliance.

    Wraps the ClauseValidator adapter, logs validation results, and
    publishes events for non-compliant contracts.

    Args:
        validator: ClauseValidator adapter instance.
        event_publisher: Domain event publisher for legal events.
    """

    def __init__(
        self,
        validator: ClauseValidator,
        event_publisher: LegalDomainEventPublisher,
    ) -> None:
        """Initialize clause validation service.

        Args:
            validator: ClauseValidator adapter.
            event_publisher: Domain event publisher.
        """
        self._validator = validator
        self._event_publisher = event_publisher

    async def validate_contract(
        self,
        contract_id: str,
        contract_type: str,
        clauses: list[dict],
        jurisdiction: str,
        tenant: TenantContext,
    ) -> dict:
        """Validate a contract's clauses and publish the result.

        Args:
            contract_id: Unique identifier of the contract.
            contract_type: Contract type for validation rules.
            clauses: List of clause dicts with clause_type and text.
            jurisdiction: Legal jurisdiction for compliance rules.
            tenant: Tenant context for RLS isolation.

        Returns:
            ValidationReport-compatible dict.
        """
        logger.info(
            "Validating contract clauses",
            contract_id=contract_id,
            contract_type=contract_type,
            clause_count=len(clauses),
            tenant_id=str(tenant.tenant_id),
        )
        report = await self._validator.validate_contract(
            contract_id=contract_id,
            contract_type=contract_type,
            clauses=clauses,
            jurisdiction=jurisdiction,
        )
        if not report.get("is_compliant", True):
            await self._event_publisher.publish(
                topic="legal.contract.compliance_violation_detected",
                payload={
                    "tenant_id": str(tenant.tenant_id),
                    "contract_id": contract_id,
                    "violation_count": report.get("violation_count", 0),
                    "missing_clause_count": report.get("missing_clause_count", 0),
                },
            )
        return report


class LiabilityAssessmentService:
    """Assesses AI system liability exposure across legal frameworks.

    Wraps the LiabilityAssessor adapter and publishes events for high-risk
    liability assessments.

    Args:
        assessor: LiabilityAssessor adapter instance.
        event_publisher: Domain event publisher for legal events.
    """

    def __init__(
        self,
        assessor: LiabilityAssessor,
        event_publisher: LegalDomainEventPublisher,
    ) -> None:
        """Initialize liability assessment service.

        Args:
            assessor: LiabilityAssessor adapter.
            event_publisher: Domain event publisher.
        """
        self._assessor = assessor
        self._event_publisher = event_publisher

    async def assess_liability(
        self,
        system_id: str,
        ai_domain: str,
        deployment_context: str,
        jurisdiction: str,
        tenant: TenantContext,
        claimed_damages_usd: float | None = None,
    ) -> dict:
        """Perform a liability assessment and publish result event.

        Args:
            system_id: Unique AI system identifier.
            ai_domain: AI application domain.
            deployment_context: Deployment context (enterprise, consumer, critical).
            jurisdiction: Legal jurisdiction for framework selection.
            tenant: Tenant context for RLS isolation.
            claimed_damages_usd: Optional claimed damages amount.

        Returns:
            LiabilityAssessmentReport-compatible dict.

        Raises:
            ValidationError: If required parameters are invalid.
        """
        if not system_id:
            raise ValidationError("system_id is required for liability assessment")

        logger.info(
            "Assessing AI liability",
            system_id=system_id,
            ai_domain=ai_domain,
            deployment_context=deployment_context,
            tenant_id=str(tenant.tenant_id),
        )
        report = await self._assessor.assess(
            system_id=system_id,
            ai_domain=ai_domain,
            deployment_context=deployment_context,
            jurisdiction=jurisdiction,
            claimed_damages_usd=claimed_damages_usd,
        )
        risk_level = report.get("overall_risk_level", "low")
        if risk_level in ("high", "critical"):
            await self._event_publisher.publish(
                topic="legal.liability.high_risk_assessment",
                payload={
                    "tenant_id": str(tenant.tenant_id),
                    "system_id": system_id,
                    "risk_level": risk_level,
                    "max_exposure_usd": report.get("max_exposure_usd", 0),
                },
            )
        return report


class IPProtectionService_Legal:
    """Manages IP asset registration and infringement risk for legal teams.

    Distinct from the manufacturing IPProtectionService, this service
    focuses on legal IP portfolio management and AI training data risk.

    Args:
        protector: IPProtector adapter instance.
        event_publisher: Domain event publisher for legal events.
    """

    def __init__(
        self,
        protector: IPProtector,
        event_publisher: LegalDomainEventPublisher,
    ) -> None:
        """Initialize IP protection legal service.

        Args:
            protector: IPProtector adapter.
            event_publisher: Domain event publisher.
        """
        self._protector = protector
        self._event_publisher = event_publisher

    async def register_asset(
        self,
        asset_name: str,
        asset_type: str,
        owner: str,
        description: str,
        tenant: TenantContext,
        filing_date: str | None = None,
    ) -> dict:
        """Register an IP asset and publish a registration event.

        Args:
            asset_name: Name of the IP asset.
            asset_type: Type of IP (patent, trademark, copyright, trade_secret).
            owner: IP owner name or identifier.
            description: Description of the IP asset.
            tenant: Tenant context for RLS isolation.
            filing_date: Optional filing or registration date.

        Returns:
            IPAsset-compatible dict.
        """
        logger.info(
            "Registering IP asset",
            asset_name=asset_name,
            asset_type=asset_type,
            owner=owner,
            tenant_id=str(tenant.tenant_id),
        )
        asset = await self._protector.register_asset(
            asset_name=asset_name,
            asset_type=asset_type,
            owner=owner,
            description=description,
            filing_date=filing_date,
        )
        await self._event_publisher.publish(
            topic="legal.ip.asset_registered",
            payload={
                "tenant_id": str(tenant.tenant_id),
                "asset_id": asset.get("asset_id"),
                "asset_name": asset_name,
                "asset_type": asset_type,
            },
        )
        return asset

    async def assess_infringement_risk(
        self,
        model_description: str,
        training_data_sources: list[str],
        use_case: str,
        tenant: TenantContext,
    ) -> dict:
        """Assess IP infringement risk for an AI model and publish a risk event.

        Args:
            model_description: Description of the AI model.
            training_data_sources: Data sources used for training.
            use_case: Intended use case.
            tenant: Tenant context for RLS isolation.

        Returns:
            InfringementRiskAssessment-compatible dict.
        """
        logger.info(
            "Assessing infringement risk",
            use_case=use_case,
            source_count=len(training_data_sources),
            tenant_id=str(tenant.tenant_id),
        )
        assessment = await self._protector.assess_infringement_risk(
            model_description=model_description,
            training_data_sources=training_data_sources,
            use_case=use_case,
        )
        risk_level = assessment.get("overall_risk_level", "low")
        if risk_level in ("high", "critical"):
            await self._event_publisher.publish(
                topic="legal.ip.high_infringement_risk_detected",
                payload={
                    "tenant_id": str(tenant.tenant_id),
                    "risk_level": risk_level,
                    "use_case": use_case,
                    "violation_count": assessment.get("potential_violations_count", 0),
                },
            )
        return assessment


class RegulatoryMonitoringService:
    """Monitors AI regulatory developments and dispatches compliance alerts.

    Wraps the RegulatoryMonitor adapter, publishes events for critical
    regulatory changes, and coordinates alert dispatch workflows.

    Args:
        monitor: RegulatoryMonitor adapter instance.
        event_publisher: Domain event publisher for legal events.
    """

    def __init__(
        self,
        monitor: RegulatoryMonitor,
        event_publisher: LegalDomainEventPublisher,
    ) -> None:
        """Initialize regulatory monitoring service.

        Args:
            monitor: RegulatoryMonitor adapter.
            event_publisher: Domain event publisher.
        """
        self._monitor = monitor
        self._event_publisher = event_publisher

    async def track_regulatory_changes(
        self,
        sector: str,
        tenant: TenantContext,
        jurisdiction: str | None = None,
    ) -> dict:
        """Monitor regulatory feeds and generate a landscape report.

        Args:
            sector: Business sector for relevance filtering.
            tenant: Tenant context for RLS isolation.
            jurisdiction: Optional jurisdiction filter.

        Returns:
            RegulatoryLandscapeReport-compatible dict.
        """
        logger.info(
            "Tracking regulatory changes",
            sector=sector,
            jurisdiction=jurisdiction,
            tenant_id=str(tenant.tenant_id),
        )
        report = await self._monitor.track_regulatory_changes(
            sector=sector,
            jurisdiction=jurisdiction,
        )
        critical_alerts = [
            a for a in report.get("alerts", [])
            if a.get("impact_level") == "critical"
        ]
        if critical_alerts:
            await self._event_publisher.publish(
                topic="legal.regulatory.critical_alert",
                payload={
                    "tenant_id": str(tenant.tenant_id),
                    "critical_alert_count": len(critical_alerts),
                    "sector": sector,
                },
            )
        return report


class LitigationSupportService_Legal:
    """Manages e-discovery workflows, TAR scoring, and production packages.

    Wraps the LitigationSupport adapter, maintains case state, and
    publishes events for production package creation.

    Args:
        support: LitigationSupport adapter instance.
        ediscovery_repository: Repository for e-discovery job persistence.
        event_publisher: Domain event publisher for legal events.
    """

    def __init__(
        self,
        support: LitigationSupport,
        ediscovery_repository: IEDiscoveryJobRepository,
        event_publisher: LegalDomainEventPublisher,
    ) -> None:
        """Initialize litigation support service.

        Args:
            support: LitigationSupport adapter.
            ediscovery_repository: Repository for e-discovery records.
            event_publisher: Domain event publisher.
        """
        self._support = support
        self._ediscovery_repo = ediscovery_repository
        self._event_publisher = event_publisher

    async def collect_document(
        self,
        document_id: str,
        document_type: str,
        content_text: str,
        custodian: str,
        case_number: str,
        tenant: TenantContext,
        metadata: dict | None = None,
    ) -> dict:
        """Collect a document into the e-discovery corpus.

        Args:
            document_id: Unique document identifier.
            document_type: Document type (email, memo, contract, etc.).
            content_text: Full text content.
            custodian: Custodian who produced the document.
            case_number: Associated case number.
            tenant: Tenant context for RLS isolation.
            metadata: Optional additional metadata.

        Returns:
            DocumentRecord-compatible dict.
        """
        logger.info(
            "Collecting e-discovery document",
            document_id=document_id,
            case_number=case_number,
            custodian=custodian,
            tenant_id=str(tenant.tenant_id),
        )
        doc_record = await self._support.collect_document(
            document_id=document_id,
            document_type=document_type,
            content_text=content_text,
            custodian=custodian,
            case_number=case_number,
            metadata=metadata,
        )
        return doc_record

    async def create_production_package(
        self,
        case_number: str,
        production_format: str,
        tenant: TenantContext,
        include_privileged: bool = False,
    ) -> dict:
        """Create a production package and publish a completion event.

        Args:
            case_number: Case number for the production.
            production_format: Output format (concordance, summation, native, pdf).
            tenant: Tenant context for RLS isolation.
            include_privileged: Whether to include privileged documents.

        Returns:
            ProductionPackage-compatible dict.
        """
        logger.info(
            "Creating production package",
            case_number=case_number,
            production_format=production_format,
            tenant_id=str(tenant.tenant_id),
        )
        package = await self._support.create_production(
            case_number=case_number,
            production_format=production_format,
            include_privileged=include_privileged,
        )
        await self._event_publisher.publish(
            topic="legal.ediscovery.production_package_created",
            payload={
                "tenant_id": str(tenant.tenant_id),
                "case_number": case_number,
                "production_id": package.get("production_id"),
                "document_count": package.get("document_count", 0),
                "production_format": production_format,
            },
        )
        return package


class PrivilegePreservationService:
    """Manages attorney-client privilege classification and clawback workflows.

    Wraps the PrivilegePreserver adapter and integrates with the existing
    PrivilegeService to coordinate privilege checks with document classification.

    Args:
        preserver: PrivilegePreserver adapter instance.
        privilege_repository: Repository for privilege check records.
        event_publisher: Domain event publisher for legal events.
    """

    def __init__(
        self,
        preserver: PrivilegePreserver,
        privilege_repository: IPrivilegeCheckRepository,
        event_publisher: LegalDomainEventPublisher,
    ) -> None:
        """Initialize privilege preservation service.

        Args:
            preserver: PrivilegePreserver adapter.
            privilege_repository: Repository for privilege check persistence.
            event_publisher: Domain event publisher.
        """
        self._preserver = preserver
        self._privilege_repo = privilege_repository
        self._event_publisher = event_publisher

    async def classify_and_record(
        self,
        document_id: str,
        document_type: str,
        content_text: str,
        tenant: TenantContext,
        metadata: dict | None = None,
    ) -> dict:
        """Classify document privilege and persist the result.

        Args:
            document_id: Unique document identifier.
            document_type: Document type.
            content_text: Full text content.
            tenant: Tenant context for RLS isolation.
            metadata: Optional metadata.

        Returns:
            PrivilegeClassification-compatible dict.
        """
        logger.info(
            "Classifying document privilege",
            document_id=document_id,
            document_type=document_type,
            tenant_id=str(tenant.tenant_id),
        )
        classification = await self._preserver.classify_document(
            document_id=document_id,
            document_type=document_type,
            content_text=content_text,
            metadata=metadata,
        )
        if classification.get("is_privileged"):
            await self._event_publisher.publish(
                topic="legal.privilege.document_classified_privileged",
                payload={
                    "tenant_id": str(tenant.tenant_id),
                    "document_id": document_id,
                    "privilege_type": classification.get("privilege_type"),
                    "confidence_score": classification.get("confidence_score", 0),
                },
            )
        return classification

    async def handle_inadvertent_disclosure(
        self,
        document_id: str,
        disclosed_to: str,
        disclosure_date: str,
        tenant: TenantContext,
        case_number: str | None = None,
    ) -> dict:
        """Initiate clawback for inadvertently disclosed privileged material.

        Args:
            document_id: Identifier of the disclosed document.
            disclosed_to: Receiving party.
            disclosure_date: Date of disclosure.
            tenant: Tenant context for RLS isolation.
            case_number: Optional associated case number.

        Returns:
            ClawbackRequest-compatible dict.
        """
        logger.info(
            "Initiating clawback for inadvertent disclosure",
            document_id=document_id,
            disclosed_to=disclosed_to,
            tenant_id=str(tenant.tenant_id),
        )
        clawback = await self._preserver.initiate_clawback(
            document_id=document_id,
            disclosed_to=disclosed_to,
            disclosure_date=disclosure_date,
            case_number=case_number,
        )
        await self._event_publisher.publish(
            topic="legal.privilege.clawback_initiated",
            payload={
                "tenant_id": str(tenant.tenant_id),
                "document_id": document_id,
                "clawback_id": clawback.get("clawback_id"),
                "disclosed_to": disclosed_to,
            },
        )
        return clawback


class LegalHoldLifecycleService:
    """Manages the full lifecycle of legal holds including compliance tracking.

    Complements the existing LegalHoldService (which manages DB records)
    by wrapping the LegalHoldManager adapter for notice generation,
    custodian tracking, and compliance monitoring workflows.

    Args:
        manager: LegalHoldManager adapter instance.
        hold_repository: Repository for legal hold record persistence.
        event_publisher: Domain event publisher for legal events.
    """

    def __init__(
        self,
        manager: LegalHoldManager,
        hold_repository: ILegalHoldRepository,
        event_publisher: LegalDomainEventPublisher,
    ) -> None:
        """Initialize legal hold lifecycle service.

        Args:
            manager: LegalHoldManager adapter.
            hold_repository: Repository for legal hold records.
            event_publisher: Domain event publisher.
        """
        self._manager = manager
        self._hold_repo = hold_repository
        self._event_publisher = event_publisher

    async def create_and_issue_hold(
        self,
        hold_name: str,
        case_name: str,
        matter_type: str,
        issuing_attorney: str,
        custodians: list[str],
        data_sources: list[str],
        tenant: TenantContext,
        case_number: str | None = None,
    ) -> dict:
        """Create a legal hold using the manager adapter and publish an event.

        Args:
            hold_name: Descriptive name for the hold.
            case_name: Associated legal matter name.
            matter_type: Type of legal matter (litigation, investigation, etc.).
            issuing_attorney: Name of the issuing attorney.
            custodians: List of custodian identifiers.
            data_sources: List of data sources to preserve.
            tenant: Tenant context for RLS isolation.
            case_number: Optional official case number.

        Returns:
            LegalHoldRecord-compatible dict from the manager adapter.

        Raises:
            ValidationError: If custodians or data_sources are empty.
        """
        if not custodians:
            raise ValidationError("At least one custodian is required")
        if not data_sources:
            raise ValidationError("At least one data source must be specified")

        logger.info(
            "Creating legal hold via manager adapter",
            hold_name=hold_name,
            case_name=case_name,
            matter_type=matter_type,
            custodian_count=len(custodians),
            tenant_id=str(tenant.tenant_id),
        )
        hold_record = await self._manager.create_hold(
            hold_name=hold_name,
            case_name=case_name,
            matter_type=matter_type,
            issuing_attorney=issuing_attorney,
            custodians=custodians,
            data_sources=data_sources,
            case_number=case_number,
        )
        await self._event_publisher.publish_legal_hold_created(
            tenant_id=tenant.tenant_id,
            hold_id=uuid.UUID(hold_record.get("hold_id", str(uuid.uuid4()))),
            hold_name=hold_name,
            custodians=custodians,
            correlation_id=str(uuid.uuid4()),
        )
        return hold_record

    async def monitor_and_send_reminders(
        self,
        hold_id: str,
        tenant: TenantContext,
    ) -> dict:
        """Monitor compliance and send reminders to unacknowledged custodians.

        Args:
            hold_id: Legal hold unique identifier.
            tenant: Tenant context for RLS isolation.

        Returns:
            Compliance status dict with pending and reminded custodians.
        """
        logger.info(
            "Monitoring hold compliance",
            hold_id=hold_id,
            tenant_id=str(tenant.tenant_id),
        )
        compliance = await self._manager.monitor_compliance(hold_id=hold_id)
        pending_count = len(compliance.get("pending_custodians", []))
        if pending_count > 0:
            await self._event_publisher.publish(
                topic="legal.hold.reminder_dispatched",
                payload={
                    "tenant_id": str(tenant.tenant_id),
                    "hold_id": hold_id,
                    "pending_count": pending_count,
                },
            )
        return compliance
