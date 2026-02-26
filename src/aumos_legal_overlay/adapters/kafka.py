"""Kafka event publishing for aumos-legal-overlay.

Defines domain events published by this service and provides
a typed publisher wrapper. All events use Topics constants and
include tenant_id and correlation_id for traceability.
"""

import uuid

from aumos_common.events import EventPublisher, Topics
from aumos_common.observability import get_logger

logger = get_logger(__name__)


class LegalDomainEventPublisher:
    """Publisher for aumos-legal-overlay domain events.

    Wraps EventPublisher with typed methods for each event type
    produced by this service.

    Args:
        publisher: The underlying EventPublisher from aumos-common.
    """

    def __init__(self, publisher: EventPublisher) -> None:
        """Initialize with the shared event publisher.

        Args:
            publisher: Configured EventPublisher instance.
        """
        self._publisher = publisher

    async def publish_privilege_checked(
        self,
        tenant_id: uuid.UUID,
        check_id: uuid.UUID,
        document_id: str,
        is_privileged: bool,
        correlation_id: str,
    ) -> None:
        """Publish a PrivilegeChecked event to Kafka.

        Signals downstream services that a privilege determination
        has been made for a document.

        Args:
            tenant_id: The tenant that owns the check.
            check_id: UUID of the privilege check.
            document_id: Document that was checked.
            is_privileged: Whether privilege was determined.
            correlation_id: Request correlation ID for tracing.
        """
        event = {
            "event_type": "privilege_checked",
            "tenant_id": str(tenant_id),
            "check_id": str(check_id),
            "document_id": document_id,
            "is_privileged": is_privileged,
            "correlation_id": correlation_id,
        }
        await self._publisher.publish(Topics.LEGAL_PRIVILEGE_CHECKED, event)
        logger.info(
            "Published PrivilegeChecked event",
            tenant_id=str(tenant_id),
            check_id=str(check_id),
            document_id=document_id,
            is_privileged=is_privileged,
        )

    async def publish_ediscovery_job_created(
        self,
        tenant_id: uuid.UUID,
        job_id: uuid.UUID,
        case_name: str,
        correlation_id: str,
    ) -> None:
        """Publish an EDiscoveryJobCreated event to Kafka.

        Signals the e-discovery processing pipeline to begin
        synthetic document generation for the job.

        Args:
            tenant_id: The tenant that owns the job.
            job_id: UUID of the e-discovery job.
            case_name: Name of the legal case.
            correlation_id: Request correlation ID for tracing.
        """
        event = {
            "event_type": "ediscovery_job_created",
            "tenant_id": str(tenant_id),
            "job_id": str(job_id),
            "case_name": case_name,
            "correlation_id": correlation_id,
        }
        await self._publisher.publish(Topics.LEGAL_EDISCOVERY_JOB_CREATED, event)
        logger.info(
            "Published EDiscoveryJobCreated event",
            tenant_id=str(tenant_id),
            job_id=str(job_id),
            case_name=case_name,
        )

    async def publish_privilege_log_entry_created(
        self,
        tenant_id: uuid.UUID,
        entry_id: uuid.UUID,
        document_id: str,
        correlation_id: str,
    ) -> None:
        """Publish a PrivilegeLogEntryCreated event to Kafka.

        Notifies downstream consumers that a new privilege log
        entry has been created for discovery response preparation.

        Args:
            tenant_id: The tenant that owns the entry.
            entry_id: UUID of the privilege log entry.
            document_id: Document referenced by the log entry.
            correlation_id: Request correlation ID for tracing.
        """
        event = {
            "event_type": "privilege_log_entry_created",
            "tenant_id": str(tenant_id),
            "entry_id": str(entry_id),
            "document_id": document_id,
            "correlation_id": correlation_id,
        }
        await self._publisher.publish(Topics.LEGAL_PRIVILEGE_LOG_ENTRY_CREATED, event)
        logger.info(
            "Published PrivilegeLogEntryCreated event",
            tenant_id=str(tenant_id),
            entry_id=str(entry_id),
            document_id=document_id,
        )

    async def publish_legal_hold_created(
        self,
        tenant_id: uuid.UUID,
        hold_id: uuid.UUID,
        hold_name: str,
        custodians: list[str],
        correlation_id: str,
    ) -> None:
        """Publish a LegalHoldCreated event to Kafka.

        Triggers custodian notification workflows for all
        custodians subject to the new legal hold.

        Args:
            tenant_id: The tenant that owns the hold.
            hold_id: UUID of the legal hold.
            hold_name: Name of the hold.
            custodians: List of custodians to notify.
            correlation_id: Request correlation ID for tracing.
        """
        event = {
            "event_type": "legal_hold_created",
            "tenant_id": str(tenant_id),
            "hold_id": str(hold_id),
            "hold_name": hold_name,
            "custodians": custodians,
            "correlation_id": correlation_id,
        }
        await self._publisher.publish(Topics.LEGAL_HOLD_CREATED, event)
        logger.info(
            "Published LegalHoldCreated event",
            tenant_id=str(tenant_id),
            hold_id=str(hold_id),
            hold_name=hold_name,
            custodian_count=len(custodians),
        )

    async def publish_legal_hold_released(
        self,
        tenant_id: uuid.UUID,
        hold_id: uuid.UUID,
        release_reason: str,
        correlation_id: str,
    ) -> None:
        """Publish a LegalHoldReleased event to Kafka.

        Notifies downstream services that a legal hold has been
        released and preservation obligations have ended.

        Args:
            tenant_id: The tenant that owns the hold.
            hold_id: UUID of the released hold.
            release_reason: Documented reason for release.
            correlation_id: Request correlation ID for tracing.
        """
        event = {
            "event_type": "legal_hold_released",
            "tenant_id": str(tenant_id),
            "hold_id": str(hold_id),
            "release_reason": release_reason,
            "correlation_id": correlation_id,
        }
        await self._publisher.publish(Topics.LEGAL_HOLD_RELEASED, event)
        logger.info(
            "Published LegalHoldReleased event",
            tenant_id=str(tenant_id),
            hold_id=str(hold_id),
            release_reason=release_reason,
        )
