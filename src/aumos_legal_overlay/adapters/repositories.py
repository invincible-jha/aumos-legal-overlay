"""SQLAlchemy repository implementations for aumos-legal-overlay.

Repositories extend BaseRepository from aumos-common which provides:
  - Automatic RLS tenant isolation (set_tenant_context)
  - Standard CRUD operations (get, list, create, update, delete)
  - Pagination support via paginate()

Only methods that differ from BaseRepository defaults are implemented here.
"""

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.auth import TenantContext
from aumos_common.database import BaseRepository

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


class PrivilegeCheckRepository(BaseRepository, IPrivilegeCheckRepository):
    """Repository for PrivilegeCheck records.

    Args:
        session: The async SQLAlchemy session (injected by FastAPI dependency).
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def get_by_id(
        self, check_id: uuid.UUID, tenant: TenantContext
    ) -> PrivilegeCheck | None:
        """Fetch a privilege check by its UUID within the tenant scope.

        Args:
            check_id: UUID of the privilege check.
            tenant: Tenant context for RLS isolation.

        Returns:
            The PrivilegeCheck or None if not found.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(PrivilegeCheck).where(
                PrivilegeCheck.id == check_id,
                PrivilegeCheck.tenant_id == tenant.tenant_id,
            )
        )
        return result.scalar_one_or_none()

    async def get_by_document_id(
        self, document_id: str, tenant: TenantContext
    ) -> list[PrivilegeCheck]:
        """Fetch all privilege checks for a document within the tenant scope.

        Args:
            document_id: Document identifier to look up.
            tenant: Tenant context for RLS isolation.

        Returns:
            List of PrivilegeCheck records for the document.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(PrivilegeCheck).where(
                PrivilegeCheck.document_id == document_id,
                PrivilegeCheck.tenant_id == tenant.tenant_id,
            )
        )
        return list(result.scalars().all())

    async def create(
        self,
        document_id: str,
        document_type: str,
        privilege_type: str,
        is_privileged: bool,
        confidence_score: float,
        metadata: dict,
        tenant: TenantContext,
        privilege_basis: str | None = None,
        reviewing_attorney: str | None = None,
    ) -> PrivilegeCheck:
        """Create a new privilege check record.

        Args:
            document_id: Document being checked.
            document_type: Type of the document.
            privilege_type: Type of privilege evaluated.
            is_privileged: Privilege determination result.
            confidence_score: ML confidence score.
            metadata: Additional document metadata.
            tenant: Tenant context.
            privilege_basis: Legal basis for claim.
            reviewing_attorney: Attorney performing the review.

        Returns:
            The newly created PrivilegeCheck.
        """
        await self.set_tenant_context(tenant)
        check = PrivilegeCheck(
            tenant_id=tenant.tenant_id,
            document_id=document_id,
            document_type=document_type,
            privilege_type=privilege_type,
            is_privileged=is_privileged,
            confidence_score=confidence_score,
            metadata=metadata,
            privilege_basis=privilege_basis,
            reviewing_attorney=reviewing_attorney,
            status="pending",
        )
        self.session.add(check)
        await self.session.flush()
        await self.session.refresh(check)
        return check

    async def update_status(
        self,
        check_id: uuid.UUID,
        status: str,
        tenant: TenantContext,
        reviewing_attorney: str | None = None,
        review_timestamp: datetime | None = None,
    ) -> PrivilegeCheck | None:
        """Update the status of an existing privilege check.

        Args:
            check_id: UUID of the check to update.
            status: New status value.
            tenant: Tenant context.
            reviewing_attorney: Updated attorney name.
            review_timestamp: When the review was completed.

        Returns:
            Updated PrivilegeCheck or None if not found.
        """
        check = await self.get_by_id(check_id, tenant)
        if check is None:
            return None
        check.status = status
        if reviewing_attorney is not None:
            check.reviewing_attorney = reviewing_attorney
        if review_timestamp is not None:
            check.review_timestamp = review_timestamp
        await self.session.flush()
        await self.session.refresh(check)
        return check

    async def list_by_status(
        self, status: str, tenant: TenantContext
    ) -> list[PrivilegeCheck]:
        """List privilege checks filtered by status.

        Args:
            status: Status to filter by.
            tenant: Tenant context for RLS isolation.

        Returns:
            List of PrivilegeCheck records matching the status.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(PrivilegeCheck).where(
                PrivilegeCheck.status == status,
                PrivilegeCheck.tenant_id == tenant.tenant_id,
            )
        )
        return list(result.scalars().all())


class EDiscoveryJobRepository(BaseRepository, IEDiscoveryJobRepository):
    """Repository for EDiscoveryJob records.

    Args:
        session: The async SQLAlchemy session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def get_by_id(
        self, job_id: uuid.UUID, tenant: TenantContext
    ) -> EDiscoveryJob | None:
        """Fetch an e-discovery job by UUID within the tenant scope.

        Args:
            job_id: UUID of the job.
            tenant: Tenant context for RLS isolation.

        Returns:
            The EDiscoveryJob or None if not found.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(EDiscoveryJob).where(
                EDiscoveryJob.id == job_id,
                EDiscoveryJob.tenant_id == tenant.tenant_id,
            )
        )
        return result.scalar_one_or_none()

    async def create(
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
        """Create a new e-discovery job.

        Args:
            case_name: Human-readable case name.
            custodians: List of custodians.
            document_types: Types of documents to generate.
            document_count_requested: Number of documents requested.
            tenant: Tenant context.
            case_number: Court case number.
            date_range_start: Start of relevant date range.
            date_range_end: End of relevant date range.
            job_metadata: Additional configuration.

        Returns:
            The newly created EDiscoveryJob.
        """
        await self.set_tenant_context(tenant)
        job = EDiscoveryJob(
            tenant_id=tenant.tenant_id,
            case_name=case_name,
            case_number=case_number,
            custodians=custodians,
            document_types=document_types,
            document_count_requested=document_count_requested,
            document_count_generated=0,
            date_range_start=date_range_start,
            date_range_end=date_range_end,
            status="queued",
            job_metadata=job_metadata or {},
        )
        self.session.add(job)
        await self.session.flush()
        await self.session.refresh(job)
        return job

    async def update_progress(
        self,
        job_id: uuid.UUID,
        document_count_generated: int,
        status: str,
        tenant: TenantContext,
        output_location: str | None = None,
        error_message: str | None = None,
    ) -> EDiscoveryJob | None:
        """Update the progress of a running e-discovery job.

        Args:
            job_id: UUID of the job to update.
            document_count_generated: Current generated document count.
            status: Updated job status.
            tenant: Tenant context.
            output_location: Where output documents are stored.
            error_message: Error details if job failed.

        Returns:
            Updated EDiscoveryJob or None if not found.
        """
        job = await self.get_by_id(job_id, tenant)
        if job is None:
            return None
        job.document_count_generated = document_count_generated
        job.status = status
        if output_location is not None:
            job.output_location = output_location
        if error_message is not None:
            job.error_message = error_message
        await self.session.flush()
        await self.session.refresh(job)
        return job

    async def list_by_case(
        self, case_number: str, tenant: TenantContext
    ) -> list[EDiscoveryJob]:
        """List e-discovery jobs for a specific case number.

        Args:
            case_number: Case number to filter by.
            tenant: Tenant context for RLS isolation.

        Returns:
            List of EDiscoveryJob records for the case.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(EDiscoveryJob).where(
                EDiscoveryJob.case_number == case_number,
                EDiscoveryJob.tenant_id == tenant.tenant_id,
            )
        )
        return list(result.scalars().all())


class AuditTrailRepository(BaseRepository, IAuditTrailRepository):
    """Repository for AuditTrail entries.

    Args:
        session: The async SQLAlchemy session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def create(
        self,
        action: str,
        actor_id: str,
        actor_type: str,
        resource_type: str,
        resource_id: str,
        action_timestamp: datetime,
        action_detail: dict,
        integrity_hash: str,
        tenant: TenantContext,
        ip_address: str | None = None,
        user_agent: str | None = None,
        previous_hash: str | None = None,
        legal_hold_id: uuid.UUID | None = None,
    ) -> AuditTrail:
        """Create an immutable audit trail entry.

        Args:
            action: Action being recorded.
            actor_id: Who performed the action.
            actor_type: Type of actor.
            resource_type: Type of resource acted upon.
            resource_id: Resource identifier.
            action_timestamp: When the action occurred.
            action_detail: Structured detail of the action.
            integrity_hash: SHA-256 integrity hash.
            tenant: Tenant context.
            ip_address: Actor IP address.
            user_agent: Actor user agent.
            previous_hash: Hash of preceding entry.
            legal_hold_id: Associated legal hold.

        Returns:
            The created AuditTrail entry.
        """
        await self.set_tenant_context(tenant)
        entry = AuditTrail(
            tenant_id=tenant.tenant_id,
            action=action,
            actor_id=actor_id,
            actor_type=actor_type,
            resource_type=resource_type,
            resource_id=resource_id,
            action_timestamp=action_timestamp,
            action_detail=action_detail,
            integrity_hash=integrity_hash,
            ip_address=ip_address,
            user_agent=user_agent,
            previous_hash=previous_hash,
            is_immutable=True,
            legal_hold_id=legal_hold_id,
        )
        self.session.add(entry)
        await self.session.flush()
        await self.session.refresh(entry)
        return entry

    async def get_by_resource(
        self,
        resource_type: str,
        resource_id: str,
        tenant: TenantContext,
    ) -> list[AuditTrail]:
        """Fetch all audit entries for a specific resource.

        Args:
            resource_type: Type of resource.
            resource_id: Resource identifier.
            tenant: Tenant context for RLS isolation.

        Returns:
            Ordered list of AuditTrail entries for the resource.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(AuditTrail)
            .where(
                AuditTrail.resource_type == resource_type,
                AuditTrail.resource_id == resource_id,
                AuditTrail.tenant_id == tenant.tenant_id,
            )
            .order_by(AuditTrail.action_timestamp)
        )
        return list(result.scalars().all())

    async def get_by_actor(
        self, actor_id: str, tenant: TenantContext
    ) -> list[AuditTrail]:
        """Fetch all audit entries for a specific actor.

        Args:
            actor_id: Actor identifier.
            tenant: Tenant context for RLS isolation.

        Returns:
            Ordered list of AuditTrail entries by this actor.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(AuditTrail)
            .where(
                AuditTrail.actor_id == actor_id,
                AuditTrail.tenant_id == tenant.tenant_id,
            )
            .order_by(AuditTrail.action_timestamp)
        )
        return list(result.scalars().all())

    async def export_range(
        self,
        start_time: datetime,
        end_time: datetime,
        tenant: TenantContext,
        resource_type: str | None = None,
    ) -> list[AuditTrail]:
        """Export audit entries within a time range.

        Args:
            start_time: Start of export window.
            end_time: End of export window.
            tenant: Tenant context for RLS isolation.
            resource_type: Optional resource type filter.

        Returns:
            Chronologically ordered list of AuditTrail entries.
        """
        await self.set_tenant_context(tenant)
        query = (
            select(AuditTrail)
            .where(
                AuditTrail.action_timestamp >= start_time,
                AuditTrail.action_timestamp <= end_time,
                AuditTrail.tenant_id == tenant.tenant_id,
            )
            .order_by(AuditTrail.action_timestamp)
        )
        if resource_type is not None:
            query = query.where(AuditTrail.resource_type == resource_type)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_latest_hash(self, tenant: TenantContext) -> str | None:
        """Retrieve the integrity hash of the most recent audit entry.

        Used to chain new entries to the existing audit log.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            The latest integrity hash or None if no entries exist.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(AuditTrail.integrity_hash)
            .where(AuditTrail.tenant_id == tenant.tenant_id)
            .order_by(AuditTrail.action_timestamp.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()


class PrivilegeLogRepository(BaseRepository, IPrivilegeLogRepository):
    """Repository for PrivilegeLog entries.

    Args:
        session: The async SQLAlchemy session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def create(
        self,
        document_id: str,
        document_type: str,
        privilege_claimed: str,
        privilege_description: str,
        subject_matter: str,
        basis_for_claim: str,
        log_entry_number: int,
        tenant: TenantContext,
        document_date: datetime | None = None,
        author: str | None = None,
        recipients: list[str] | None = None,
        privilege_check_id: uuid.UUID | None = None,
        case_number: str | None = None,
        is_redacted: bool = False,
    ) -> PrivilegeLog:
        """Create a new privilege log entry.

        Args:
            document_id: Document identifier.
            document_type: Type of document.
            privilege_claimed: Type of privilege.
            privilege_description: Description of the privilege.
            subject_matter: Subject matter of the document.
            basis_for_claim: Legal basis.
            log_entry_number: Sequential entry number.
            tenant: Tenant context.
            document_date: Date of the document.
            author: Document author.
            recipients: Document recipients.
            privilege_check_id: Linked privilege check.
            case_number: Associated case number.
            is_redacted: Whether the document is redacted.

        Returns:
            The created PrivilegeLog entry.
        """
        await self.set_tenant_context(tenant)
        entry = PrivilegeLog(
            tenant_id=tenant.tenant_id,
            document_id=document_id,
            document_type=document_type,
            privilege_claimed=privilege_claimed,
            privilege_description=privilege_description,
            subject_matter=subject_matter,
            basis_for_claim=basis_for_claim,
            log_entry_number=log_entry_number,
            document_date=document_date,
            author=author,
            recipients=recipients or [],
            privilege_check_id=privilege_check_id,
            case_number=case_number,
            is_redacted=is_redacted,
        )
        self.session.add(entry)
        await self.session.flush()
        await self.session.refresh(entry)
        return entry

    async def list_by_case(
        self, case_number: str, tenant: TenantContext
    ) -> list[PrivilegeLog]:
        """List privilege log entries for a specific case.

        Args:
            case_number: Case number to filter by.
            tenant: Tenant context for RLS isolation.

        Returns:
            Log entries ordered by entry number.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(PrivilegeLog)
            .where(
                PrivilegeLog.case_number == case_number,
                PrivilegeLog.tenant_id == tenant.tenant_id,
            )
            .order_by(PrivilegeLog.log_entry_number)
        )
        return list(result.scalars().all())

    async def get_next_entry_number(
        self, case_number: str, tenant: TenantContext
    ) -> int:
        """Determine the next sequential entry number for a case.

        Args:
            case_number: Case number to check.
            tenant: Tenant context for RLS isolation.

        Returns:
            The next available entry number (1-based).
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(func.max(PrivilegeLog.log_entry_number)).where(
                PrivilegeLog.case_number == case_number,
                PrivilegeLog.tenant_id == tenant.tenant_id,
            )
        )
        max_number = result.scalar_one_or_none()
        return (max_number or 0) + 1

    async def list_all(self, tenant: TenantContext) -> list[PrivilegeLog]:
        """List all privilege log entries for the tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            All PrivilegeLog entries ordered by entry number.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(PrivilegeLog)
            .where(PrivilegeLog.tenant_id == tenant.tenant_id)
            .order_by(PrivilegeLog.log_entry_number)
        )
        return list(result.scalars().all())


class LegalHoldRepository(BaseRepository, ILegalHoldRepository):
    """Repository for LegalHold records.

    Args:
        session: The async SQLAlchemy session.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize repository with database session.

        Args:
            session: Async SQLAlchemy session.
        """
        super().__init__(session)

    async def get_by_id(
        self, hold_id: uuid.UUID, tenant: TenantContext
    ) -> LegalHold | None:
        """Fetch a legal hold by UUID within the tenant scope.

        Args:
            hold_id: UUID of the legal hold.
            tenant: Tenant context for RLS isolation.

        Returns:
            The LegalHold or None if not found.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(LegalHold).where(
                LegalHold.id == hold_id,
                LegalHold.tenant_id == tenant.tenant_id,
            )
        )
        return result.scalar_one_or_none()

    async def create(
        self,
        hold_name: str,
        case_name: str,
        matter_type: str,
        issuing_attorney: str,
        custodians: list[str],
        data_sources: list[str],
        hold_issued_at: datetime,
        tenant: TenantContext,
        case_number: str | None = None,
        hold_expires_at: datetime | None = None,
        hold_metadata: dict | None = None,
    ) -> LegalHold:
        """Create a new legal hold record.

        Args:
            hold_name: Name of the hold.
            case_name: Name of the case.
            matter_type: Type of legal matter.
            issuing_attorney: Attorney issuing the hold.
            custodians: Custodians subject to the hold.
            data_sources: Data sources to preserve.
            hold_issued_at: When the hold was issued.
            tenant: Tenant context.
            case_number: Official case number.
            hold_expires_at: Expiration date.
            hold_metadata: Additional configuration.

        Returns:
            The created LegalHold.
        """
        await self.set_tenant_context(tenant)
        hold = LegalHold(
            tenant_id=tenant.tenant_id,
            hold_name=hold_name,
            case_name=case_name,
            case_number=case_number,
            matter_type=matter_type,
            issuing_attorney=issuing_attorney,
            custodians=custodians,
            custodian_acknowledgements={},
            data_sources=data_sources,
            hold_issued_at=hold_issued_at,
            hold_expires_at=hold_expires_at,
            status="active",
            hold_metadata=hold_metadata or {},
        )
        self.session.add(hold)
        await self.session.flush()
        await self.session.refresh(hold)
        return hold

    async def update_status(
        self,
        hold_id: uuid.UUID,
        status: str,
        tenant: TenantContext,
        release_reason: str | None = None,
    ) -> LegalHold | None:
        """Update the status of a legal hold.

        Args:
            hold_id: UUID of the hold to update.
            status: New status value.
            tenant: Tenant context.
            release_reason: Reason for status change.

        Returns:
            Updated LegalHold or None if not found.
        """
        hold = await self.get_by_id(hold_id, tenant)
        if hold is None:
            return None
        hold.status = status
        if release_reason is not None:
            hold.release_reason = release_reason
        await self.session.flush()
        await self.session.refresh(hold)
        return hold

    async def record_acknowledgement(
        self,
        hold_id: uuid.UUID,
        custodian: str,
        acknowledged_at: datetime,
        tenant: TenantContext,
    ) -> LegalHold | None:
        """Record a custodian's acknowledgement of a legal hold.

        Args:
            hold_id: UUID of the legal hold.
            custodian: Custodian identifier acknowledging the hold.
            acknowledged_at: Timestamp of acknowledgement.
            tenant: Tenant context.

        Returns:
            Updated LegalHold or None if not found.
        """
        hold = await self.get_by_id(hold_id, tenant)
        if hold is None:
            return None
        hold.custodian_acknowledgements[custodian] = acknowledged_at.isoformat()
        await self.session.flush()
        await self.session.refresh(hold)
        return hold

    async def update_reminder_timestamp(
        self, hold_id: uuid.UUID, reminded_at: datetime, tenant: TenantContext
    ) -> LegalHold | None:
        """Record when the last hold reminder was sent.

        Args:
            hold_id: UUID of the legal hold.
            reminded_at: Timestamp of the reminder.
            tenant: Tenant context.

        Returns:
            Updated LegalHold or None if not found.
        """
        hold = await self.get_by_id(hold_id, tenant)
        if hold is None:
            return None
        hold.last_reminder_sent_at = reminded_at
        await self.session.flush()
        await self.session.refresh(hold)
        return hold

    async def list_active(self, tenant: TenantContext) -> list[LegalHold]:
        """List all active legal holds for the tenant.

        Args:
            tenant: Tenant context for RLS isolation.

        Returns:
            List of active LegalHold records.
        """
        await self.set_tenant_context(tenant)
        result = await self.session.execute(
            select(LegalHold).where(
                LegalHold.status == "active",
                LegalHold.tenant_id == tenant.tenant_id,
            )
        )
        return list(result.scalars().all())
