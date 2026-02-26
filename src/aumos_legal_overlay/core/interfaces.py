"""Abstract interfaces (Protocol classes) for aumos-legal-overlay.

Services depend on interfaces, not concrete implementations,
enabling dependency injection and easy test mocking.
"""

import uuid
from datetime import datetime
from typing import Protocol, runtime_checkable

from aumos_common.auth import TenantContext

from aumos_legal_overlay.core.models import (
    AuditTrail,
    EDiscoveryJob,
    LegalHold,
    PrivilegeCheck,
    PrivilegeLog,
)


@runtime_checkable
class IPrivilegeCheckRepository(Protocol):
    """Repository interface for PrivilegeCheck records."""

    async def get_by_id(
        self, check_id: uuid.UUID, tenant: TenantContext
    ) -> PrivilegeCheck | None: ...

    async def get_by_document_id(
        self, document_id: str, tenant: TenantContext
    ) -> list[PrivilegeCheck]: ...

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
    ) -> PrivilegeCheck: ...

    async def update_status(
        self,
        check_id: uuid.UUID,
        status: str,
        tenant: TenantContext,
        reviewing_attorney: str | None = None,
        review_timestamp: datetime | None = None,
    ) -> PrivilegeCheck | None: ...

    async def list_by_status(
        self, status: str, tenant: TenantContext
    ) -> list[PrivilegeCheck]: ...


@runtime_checkable
class IEDiscoveryJobRepository(Protocol):
    """Repository interface for EDiscoveryJob records."""

    async def get_by_id(
        self, job_id: uuid.UUID, tenant: TenantContext
    ) -> EDiscoveryJob | None: ...

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
    ) -> EDiscoveryJob: ...

    async def update_progress(
        self,
        job_id: uuid.UUID,
        document_count_generated: int,
        status: str,
        tenant: TenantContext,
        output_location: str | None = None,
        error_message: str | None = None,
    ) -> EDiscoveryJob | None: ...

    async def list_by_case(
        self, case_number: str, tenant: TenantContext
    ) -> list[EDiscoveryJob]: ...


@runtime_checkable
class IAuditTrailRepository(Protocol):
    """Repository interface for AuditTrail entries."""

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
    ) -> AuditTrail: ...

    async def get_by_resource(
        self,
        resource_type: str,
        resource_id: str,
        tenant: TenantContext,
    ) -> list[AuditTrail]: ...

    async def get_by_actor(
        self, actor_id: str, tenant: TenantContext
    ) -> list[AuditTrail]: ...

    async def export_range(
        self,
        start_time: datetime,
        end_time: datetime,
        tenant: TenantContext,
        resource_type: str | None = None,
    ) -> list[AuditTrail]: ...

    async def get_latest_hash(self, tenant: TenantContext) -> str | None: ...


@runtime_checkable
class IPrivilegeLogRepository(Protocol):
    """Repository interface for PrivilegeLog entries."""

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
    ) -> PrivilegeLog: ...

    async def list_by_case(
        self, case_number: str, tenant: TenantContext
    ) -> list[PrivilegeLog]: ...

    async def get_next_entry_number(
        self, case_number: str, tenant: TenantContext
    ) -> int: ...

    async def list_all(self, tenant: TenantContext) -> list[PrivilegeLog]: ...


@runtime_checkable
class ILegalHoldRepository(Protocol):
    """Repository interface for LegalHold records."""

    async def get_by_id(
        self, hold_id: uuid.UUID, tenant: TenantContext
    ) -> LegalHold | None: ...

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
    ) -> LegalHold: ...

    async def update_status(
        self,
        hold_id: uuid.UUID,
        status: str,
        tenant: TenantContext,
        release_reason: str | None = None,
    ) -> LegalHold | None: ...

    async def record_acknowledgement(
        self,
        hold_id: uuid.UUID,
        custodian: str,
        acknowledged_at: datetime,
        tenant: TenantContext,
    ) -> LegalHold | None: ...

    async def update_reminder_timestamp(
        self, hold_id: uuid.UUID, reminded_at: datetime, tenant: TenantContext
    ) -> LegalHold | None: ...

    async def list_active(self, tenant: TenantContext) -> list[LegalHold]: ...


__all__ = [
    "IPrivilegeCheckRepository",
    "IEDiscoveryJobRepository",
    "IAuditTrailRepository",
    "IPrivilegeLogRepository",
    "ILegalHoldRepository",
]
