"""Unit tests for aumos-legal-overlay service layer.

Tests business logic in isolation using mock repositories and publishers.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aumos_common.auth import TenantContext
from aumos_common.errors import NotFoundError, ValidationError

from aumos_legal_overlay.adapters.kafka import LegalDomainEventPublisher
from aumos_legal_overlay.core.models import (
    AuditTrail,
    EDiscoveryJob,
    LegalHold,
    PrivilegeCheck,
    PrivilegeLog,
)
from aumos_legal_overlay.core.services import (
    AuditTrailService,
    EDiscoveryService,
    LegalHoldService,
    PrivilegeLogService,
    PrivilegeService,
)


@pytest.fixture
def tenant() -> TenantContext:
    """Provide a test tenant context.

    Returns:
        TenantContext with a fixed tenant UUID.
    """
    return TenantContext(tenant_id=uuid.uuid4(), user_id=uuid.uuid4())


@pytest.fixture
def mock_event_publisher() -> LegalDomainEventPublisher:
    """Provide a mock event publisher.

    Returns:
        LegalDomainEventPublisher with all methods mocked as AsyncMock.
    """
    publisher = MagicMock(spec=LegalDomainEventPublisher)
    publisher.publish_privilege_checked = AsyncMock()
    publisher.publish_ediscovery_job_created = AsyncMock()
    publisher.publish_privilege_log_entry_created = AsyncMock()
    publisher.publish_legal_hold_created = AsyncMock()
    publisher.publish_legal_hold_released = AsyncMock()
    return publisher


# ---------------------------------------------------------------------------
# PrivilegeService tests
# ---------------------------------------------------------------------------


class TestPrivilegeService:
    """Tests for PrivilegeService business logic."""

    @pytest.fixture
    def mock_repo(self) -> AsyncMock:
        """Provide a mock privilege check repository."""
        return AsyncMock()

    @pytest.fixture
    def service(
        self,
        mock_repo: AsyncMock,
        mock_event_publisher: LegalDomainEventPublisher,
    ) -> PrivilegeService:
        """Provide a configured PrivilegeService with mocked dependencies."""
        return PrivilegeService(
            repository=mock_repo,
            event_publisher=mock_event_publisher,
            confidence_threshold=0.85,
        )

    @pytest.mark.asyncio
    async def test_check_privilege_above_threshold_marks_privileged(
        self,
        service: PrivilegeService,
        mock_repo: AsyncMock,
        tenant: TenantContext,
        mock_event_publisher: LegalDomainEventPublisher,
    ) -> None:
        """Documents with confidence above threshold must be marked privileged."""
        expected_check = MagicMock(spec=PrivilegeCheck)
        expected_check.id = uuid.uuid4()
        mock_repo.create.return_value = expected_check

        result = await service.check_privilege(
            document_id="doc-001",
            document_type="email",
            privilege_type="attorney_client",
            confidence_score=0.92,
            metadata={},
            tenant=tenant,
        )

        mock_repo.create.assert_called_once()
        call_kwargs = mock_repo.create.call_args.kwargs
        assert call_kwargs["is_privileged"] is True
        mock_event_publisher.publish_privilege_checked.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_check_privilege_below_threshold_marks_not_privileged(
        self,
        service: PrivilegeService,
        mock_repo: AsyncMock,
        tenant: TenantContext,
        mock_event_publisher: LegalDomainEventPublisher,
    ) -> None:
        """Documents with confidence below threshold must not be marked privileged."""
        expected_check = MagicMock(spec=PrivilegeCheck)
        expected_check.id = uuid.uuid4()
        mock_repo.create.return_value = expected_check

        await service.check_privilege(
            document_id="doc-002",
            document_type="memo",
            privilege_type="work_product",
            confidence_score=0.50,
            metadata={},
            tenant=tenant,
        )

        call_kwargs = mock_repo.create.call_args.kwargs
        assert call_kwargs["is_privileged"] is False

    @pytest.mark.asyncio
    async def test_check_privilege_invalid_score_raises_validation_error(
        self,
        service: PrivilegeService,
        tenant: TenantContext,
    ) -> None:
        """Confidence scores outside [0.0, 1.0] must raise ValidationError."""
        with pytest.raises(ValidationError):
            await service.check_privilege(
                document_id="doc-003",
                document_type="email",
                privilege_type="attorney_client",
                confidence_score=1.5,
                metadata={},
                tenant=tenant,
            )

    @pytest.mark.asyncio
    async def test_get_privilege_status_not_found_raises_error(
        self,
        service: PrivilegeService,
        mock_repo: AsyncMock,
        tenant: TenantContext,
    ) -> None:
        """get_privilege_status must raise NotFoundError for unknown IDs."""
        mock_repo.get_by_id.return_value = None

        with pytest.raises(NotFoundError):
            await service.get_privilege_status(uuid.uuid4(), tenant)


# ---------------------------------------------------------------------------
# EDiscoveryService tests
# ---------------------------------------------------------------------------


class TestEDiscoveryService:
    """Tests for EDiscoveryService business logic."""

    @pytest.fixture
    def mock_repo(self) -> AsyncMock:
        """Provide a mock e-discovery job repository."""
        return AsyncMock()

    @pytest.fixture
    def service(
        self,
        mock_repo: AsyncMock,
        mock_event_publisher: LegalDomainEventPublisher,
    ) -> EDiscoveryService:
        """Provide a configured EDiscoveryService with mocked dependencies."""
        return EDiscoveryService(
            repository=mock_repo,
            event_publisher=mock_event_publisher,
        )

    @pytest.mark.asyncio
    async def test_generate_creates_queued_job(
        self,
        service: EDiscoveryService,
        mock_repo: AsyncMock,
        tenant: TenantContext,
        mock_event_publisher: LegalDomainEventPublisher,
    ) -> None:
        """generate_ediscovery_data must create a job and publish an event."""
        expected_job = MagicMock(spec=EDiscoveryJob)
        expected_job.id = uuid.uuid4()
        mock_repo.create.return_value = expected_job

        result = await service.generate_ediscovery_data(
            case_name="Smith v. Jones",
            custodians=["alice@example.com", "bob@example.com"],
            document_types=["email", "memo"],
            document_count_requested=500,
            tenant=tenant,
            case_number="2024-CV-001",
        )

        mock_repo.create.assert_called_once()
        mock_event_publisher.publish_ediscovery_job_created.assert_awaited_once()
        assert result == expected_job

    @pytest.mark.asyncio
    async def test_generate_zero_documents_raises_validation_error(
        self,
        service: EDiscoveryService,
        tenant: TenantContext,
    ) -> None:
        """Requesting zero documents must raise ValidationError."""
        with pytest.raises(ValidationError):
            await service.generate_ediscovery_data(
                case_name="Test Case",
                custodians=["alice@example.com"],
                document_types=["email"],
                document_count_requested=0,
                tenant=tenant,
            )

    @pytest.mark.asyncio
    async def test_generate_empty_custodians_raises_validation_error(
        self,
        service: EDiscoveryService,
        tenant: TenantContext,
    ) -> None:
        """Empty custodian list must raise ValidationError."""
        with pytest.raises(ValidationError):
            await service.generate_ediscovery_data(
                case_name="Test Case",
                custodians=[],
                document_types=["email"],
                document_count_requested=100,
                tenant=tenant,
            )


# ---------------------------------------------------------------------------
# AuditTrailService tests
# ---------------------------------------------------------------------------


class TestAuditTrailService:
    """Tests for AuditTrailService business logic."""

    @pytest.fixture
    def mock_repo(self) -> AsyncMock:
        """Provide a mock audit trail repository."""
        return AsyncMock()

    @pytest.fixture
    def service(
        self,
        mock_repo: AsyncMock,
        mock_event_publisher: LegalDomainEventPublisher,
    ) -> AuditTrailService:
        """Provide a configured AuditTrailService with mocked dependencies."""
        return AuditTrailService(
            repository=mock_repo,
            event_publisher=mock_event_publisher,
        )

    @pytest.mark.asyncio
    async def test_record_action_creates_chained_entry(
        self,
        service: AuditTrailService,
        mock_repo: AsyncMock,
        tenant: TenantContext,
    ) -> None:
        """record_action must chain to the latest hash and create an entry."""
        mock_repo.get_latest_hash.return_value = "abc123previoushash"
        expected_entry = MagicMock(spec=AuditTrail)
        mock_repo.create.return_value = expected_entry

        result = await service.record_action(
            action="document_accessed",
            actor_id="user-001",
            actor_type="user",
            resource_type="document",
            resource_id="doc-001",
            action_detail={"purpose": "review"},
            tenant=tenant,
        )

        call_kwargs = mock_repo.create.call_args.kwargs
        assert call_kwargs["previous_hash"] == "abc123previoushash"
        assert len(call_kwargs["integrity_hash"]) == 64  # SHA-256 hex
        assert result == expected_entry

    @pytest.mark.asyncio
    async def test_export_invalid_time_range_raises_validation_error(
        self,
        service: AuditTrailService,
        tenant: TenantContext,
    ) -> None:
        """Exporting with end_time before start_time must raise ValidationError."""
        end_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
        start_time = datetime(2024, 6, 1, tzinfo=timezone.utc)

        with pytest.raises(ValidationError):
            await service.export_audit_trail(start_time, end_time, tenant)

    def test_integrity_hash_is_deterministic(
        self,
        service: AuditTrailService,
        tenant: TenantContext,
    ) -> None:
        """Same input must always produce the same integrity hash."""
        timestamp = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        hash1 = service._compute_integrity_hash(
            action="test_action",
            actor_id="user-001",
            resource_type="document",
            resource_id="doc-001",
            action_timestamp=timestamp,
            action_detail={"key": "value"},
            previous_hash="prev_hash",
            tenant_id=tenant.tenant_id,
        )
        hash2 = service._compute_integrity_hash(
            action="test_action",
            actor_id="user-001",
            resource_type="document",
            resource_id="doc-001",
            action_timestamp=timestamp,
            action_detail={"key": "value"},
            previous_hash="prev_hash",
            tenant_id=tenant.tenant_id,
        )

        assert hash1 == hash2
        assert len(hash1) == 64

    def test_integrity_hash_changes_with_different_input(
        self,
        service: AuditTrailService,
        tenant: TenantContext,
    ) -> None:
        """Different inputs must produce different integrity hashes."""
        timestamp = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        hash_a = service._compute_integrity_hash(
            action="action_a",
            actor_id="user-001",
            resource_type="document",
            resource_id="doc-001",
            action_timestamp=timestamp,
            action_detail={},
            previous_hash=None,
            tenant_id=tenant.tenant_id,
        )
        hash_b = service._compute_integrity_hash(
            action="action_b",
            actor_id="user-001",
            resource_type="document",
            resource_id="doc-001",
            action_timestamp=timestamp,
            action_detail={},
            previous_hash=None,
            tenant_id=tenant.tenant_id,
        )

        assert hash_a != hash_b


# ---------------------------------------------------------------------------
# LegalHoldService tests
# ---------------------------------------------------------------------------


class TestLegalHoldService:
    """Tests for LegalHoldService business logic."""

    @pytest.fixture
    def mock_repo(self) -> AsyncMock:
        """Provide a mock legal hold repository."""
        return AsyncMock()

    @pytest.fixture
    def service(
        self,
        mock_repo: AsyncMock,
        mock_event_publisher: LegalDomainEventPublisher,
    ) -> LegalHoldService:
        """Provide a configured LegalHoldService with mocked dependencies."""
        return LegalHoldService(
            repository=mock_repo,
            event_publisher=mock_event_publisher,
        )

    @pytest.mark.asyncio
    async def test_create_legal_hold_publishes_event(
        self,
        service: LegalHoldService,
        mock_repo: AsyncMock,
        tenant: TenantContext,
        mock_event_publisher: LegalDomainEventPublisher,
    ) -> None:
        """create_legal_hold must persist the hold and publish a notification event."""
        expected_hold = MagicMock(spec=LegalHold)
        expected_hold.id = uuid.uuid4()
        mock_repo.create.return_value = expected_hold

        result = await service.create_legal_hold(
            hold_name="Smith v. Jones Hold",
            case_name="Smith v. Jones",
            matter_type="litigation",
            issuing_attorney="Jane Doe, Esq.",
            custodians=["alice@example.com"],
            data_sources=["email", "sharepoint"],
            tenant=tenant,
        )

        mock_repo.create.assert_called_once()
        mock_event_publisher.publish_legal_hold_created.assert_awaited_once()
        assert result == expected_hold

    @pytest.mark.asyncio
    async def test_create_hold_empty_custodians_raises_validation_error(
        self,
        service: LegalHoldService,
        tenant: TenantContext,
    ) -> None:
        """Empty custodians must raise ValidationError."""
        with pytest.raises(ValidationError):
            await service.create_legal_hold(
                hold_name="Test Hold",
                case_name="Test Case",
                matter_type="litigation",
                issuing_attorney="Jane Doe",
                custodians=[],
                data_sources=["email"],
                tenant=tenant,
            )

    @pytest.mark.asyncio
    async def test_create_hold_empty_data_sources_raises_validation_error(
        self,
        service: LegalHoldService,
        tenant: TenantContext,
    ) -> None:
        """Empty data_sources must raise ValidationError."""
        with pytest.raises(ValidationError):
            await service.create_legal_hold(
                hold_name="Test Hold",
                case_name="Test Case",
                matter_type="litigation",
                issuing_attorney="Jane Doe",
                custodians=["alice@example.com"],
                data_sources=[],
                tenant=tenant,
            )

    @pytest.mark.asyncio
    async def test_release_hold_not_found_raises_error(
        self,
        service: LegalHoldService,
        mock_repo: AsyncMock,
        tenant: TenantContext,
    ) -> None:
        """release_hold must raise NotFoundError for unknown hold IDs."""
        mock_repo.get_by_id.return_value = None

        with pytest.raises(NotFoundError):
            await service.release_hold(uuid.uuid4(), "Case settled", tenant)

    @pytest.mark.asyncio
    async def test_release_already_released_hold_raises_validation_error(
        self,
        service: LegalHoldService,
        mock_repo: AsyncMock,
        tenant: TenantContext,
    ) -> None:
        """Releasing an already-released hold must raise ValidationError."""
        hold = MagicMock(spec=LegalHold)
        hold.id = uuid.uuid4()
        hold.status = "released"
        mock_repo.get_by_id.return_value = hold

        with pytest.raises(ValidationError):
            await service.release_hold(hold.id, "Case settled", tenant)
