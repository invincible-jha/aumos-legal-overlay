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
    "IContractSynthesizerProtocol",
    "IClauseValidatorProtocol",
    "ILiabilityAssessorProtocol",
    "IIPProtectorProtocol",
    "IRegulatoryMonitorProtocol",
    "ILitigationSupportProtocol",
    "IPrivilegePreserverProtocol",
    "ILegalHoldManagerProtocol",
]


# ---------------------------------------------------------------------------
# New adapter protocols for Phase 5 legal overlay extensions
# ---------------------------------------------------------------------------


@runtime_checkable
class IContractSynthesizerProtocol(Protocol):
    """Protocol for synthetic legal contract generation.

    Implementations generate realistic legal documents (NDA, MSA, SLA,
    Employment, Vendor) for AI training data and contract analysis systems.
    """

    async def synthesize_contract(
        self,
        contract_type: str,
        jurisdiction: str = "US-NY",
        complexity: str = "standard",
        party_count: int = 2,
        metadata: dict | None = None,
    ) -> dict:
        """Synthesize a single legal contract document.

        Args:
            contract_type: Type of contract to generate (NDA, MSA, SLA, etc.).
            jurisdiction: Legal jurisdiction for language adaptation.
            complexity: Clause complexity level (simple, standard, complex).
            party_count: Number of contract parties.
            metadata: Optional metadata to attach to the contract.

        Returns:
            Dict with contract_id, assembled_text, sections, and metadata.
        """
        ...

    async def generate_batch(
        self,
        count: int,
        contract_types: list[str] | None = None,
    ) -> list[dict]:
        """Generate a batch of synthetic contracts.

        Args:
            count: Number of contracts to generate.
            contract_types: Optional list of contract types to draw from.

        Returns:
            List of contract dicts.
        """
        ...


@runtime_checkable
class IClauseValidatorProtocol(Protocol):
    """Protocol for legal clause compliance validation.

    Implementations validate contract clauses against applicable regulations,
    detect missing required clauses, and identify conflicting clauses.
    """

    async def validate_contract(
        self,
        contract_id: str,
        contract_type: str,
        clauses: list[dict],
        jurisdiction: str = "US-NY",
    ) -> dict:
        """Validate all clauses in a contract for regulatory compliance.

        Args:
            contract_id: Unique identifier of the contract.
            contract_type: Type of contract being validated.
            clauses: List of clause dicts with clause_type and text.
            jurisdiction: Jurisdiction for compliance checking.

        Returns:
            ValidationReport-compatible dict with compliance status and findings.
        """
        ...

    async def score_clause(
        self,
        clause_type: str,
        clause_text: str,
        jurisdiction: str = "US-NY",
    ) -> dict:
        """Score a single clause for regulatory compliance.

        Args:
            clause_type: Type/category of the clause.
            clause_text: Full text of the clause to evaluate.
            jurisdiction: Applicable legal jurisdiction.

        Returns:
            ClauseComplianceResult-compatible dict.
        """
        ...


@runtime_checkable
class ILiabilityAssessorProtocol(Protocol):
    """Protocol for AI-specific liability assessment.

    Implementations evaluate liability exposure across legal frameworks
    (negligence, strict liability, product liability) for AI systems.
    """

    async def assess(
        self,
        system_id: str,
        ai_domain: str,
        deployment_context: str,
        jurisdiction: str = "US",
        claimed_damages_usd: float | None = None,
    ) -> dict:
        """Perform a full liability assessment for an AI system.

        Args:
            system_id: Unique identifier for the AI system.
            ai_domain: AI application domain (medical, financial, autonomous, etc.).
            deployment_context: Deployment context (enterprise, consumer, critical).
            jurisdiction: Legal jurisdiction for framework selection.
            claimed_damages_usd: Optional claimed damages for exposure modeling.

        Returns:
            LiabilityAssessmentReport-compatible dict.
        """
        ...


@runtime_checkable
class IIPProtectorProtocol(Protocol):
    """Protocol for intellectual property protection analysis.

    Implementations manage IP asset registration, infringement risk
    assessment, model IP classification, and portfolio reporting for AI.
    """

    async def register_asset(
        self,
        asset_name: str,
        asset_type: str,
        owner: str,
        description: str,
        filing_date: str | None = None,
    ) -> dict:
        """Register a new IP asset in the protection registry.

        Args:
            asset_name: Name of the IP asset.
            asset_type: Type of IP (patent, trademark, copyright, trade_secret).
            owner: Name or ID of the IP owner.
            description: Description of the IP asset.
            filing_date: Optional filing or registration date.

        Returns:
            IPAsset-compatible dict.
        """
        ...

    async def assess_infringement_risk(
        self,
        model_description: str,
        training_data_sources: list[str],
        use_case: str,
    ) -> dict:
        """Assess infringement risk for a proposed AI model or use case.

        Args:
            model_description: Description of the AI model.
            training_data_sources: List of data sources used for training.
            use_case: Intended use case for the model.

        Returns:
            InfringementRiskAssessment-compatible dict.
        """
        ...


@runtime_checkable
class IRegulatoryMonitorProtocol(Protocol):
    """Protocol for AI regulatory monitoring and alerting.

    Implementations track emerging AI regulations, score relevance to
    specific sectors, and dispatch compliance alerts to stakeholders.
    """

    async def track_regulatory_changes(
        self,
        sector: str = "general",
        jurisdiction: str | None = None,
    ) -> dict:
        """Monitor regulatory feeds and generate landscape report.

        Args:
            sector: Business sector for relevance filtering.
            jurisdiction: Optional jurisdiction filter.

        Returns:
            RegulatoryLandscapeReport-compatible dict.
        """
        ...

    async def generate_alert(
        self,
        regulation_id: str,
        impact_level: str,
        sector: str,
    ) -> dict:
        """Generate a regulatory alert for a specific regulation.

        Args:
            regulation_id: Regulation identifier.
            impact_level: Impact level (critical, high, medium, low).
            sector: Target sector for the alert.

        Returns:
            RegulatoryAlert-compatible dict.
        """
        ...


@runtime_checkable
class ILitigationSupportProtocol(Protocol):
    """Protocol for e-discovery litigation support.

    Implementations manage document collection, privilege review, TAR
    (Technology Assisted Review) scoring, and production package creation.
    """

    async def collect_document(
        self,
        document_id: str,
        document_type: str,
        content_text: str,
        custodian: str,
        case_number: str,
        metadata: dict | None = None,
    ) -> dict:
        """Collect a document into the e-discovery corpus.

        Args:
            document_id: Unique document identifier.
            document_type: Type of document (email, memo, contract, etc.).
            content_text: Text content of the document.
            custodian: Custodian who produced the document.
            case_number: Associated case number.
            metadata: Optional additional metadata.

        Returns:
            DocumentRecord-compatible dict.
        """
        ...

    async def create_production(
        self,
        case_number: str,
        production_format: str = "concordance",
        include_privileged: bool = False,
    ) -> dict:
        """Create a production package for a case.

        Args:
            case_number: Case number to create production for.
            production_format: Output format (concordance, summation, native, pdf).
            include_privileged: Whether to include privileged documents.

        Returns:
            ProductionPackage-compatible dict.
        """
        ...


@runtime_checkable
class IPrivilegePreserverProtocol(Protocol):
    """Protocol for attorney-client privilege preservation.

    Implementations classify documents for privilege, maintain privilege
    logs, perform redactions, and handle inadvertent disclosure clawbacks.
    """

    async def classify_document(
        self,
        document_id: str,
        document_type: str,
        content_text: str,
        metadata: dict | None = None,
    ) -> dict:
        """Classify a document for attorney-client or work product privilege.

        Args:
            document_id: Unique document identifier.
            document_type: Type of document.
            content_text: Full text content.
            metadata: Optional document metadata.

        Returns:
            PrivilegeClassification-compatible dict.
        """
        ...

    async def initiate_clawback(
        self,
        document_id: str,
        disclosed_to: str,
        disclosure_date: str,
        case_number: str | None = None,
    ) -> dict:
        """Initiate a clawback request for inadvertently disclosed privileged material.

        Args:
            document_id: Identifier of the inadvertently disclosed document.
            disclosed_to: Party to whom the document was disclosed.
            disclosure_date: Date of the disclosure.
            case_number: Optional associated case number.

        Returns:
            ClawbackRequest-compatible dict.
        """
        ...


@runtime_checkable
class ILegalHoldManagerProtocol(Protocol):
    """Protocol for legal hold lifecycle management.

    Implementations manage hold creation, custodian notification,
    acknowledgement tracking, compliance monitoring, and hold release.
    """

    async def create_hold(
        self,
        hold_name: str,
        case_name: str,
        matter_type: str,
        issuing_attorney: str,
        custodians: list[str],
        data_sources: list[str],
        case_number: str | None = None,
    ) -> dict:
        """Create and issue a new legal hold.

        Args:
            hold_name: Descriptive name for the legal hold.
            case_name: Associated legal matter name.
            matter_type: Type of legal matter.
            issuing_attorney: Name of the issuing attorney.
            custodians: List of custodian identifiers.
            data_sources: List of data sources to preserve.
            case_number: Optional official case number.

        Returns:
            LegalHoldRecord-compatible dict.
        """
        ...

    async def monitor_compliance(
        self,
        hold_id: str,
    ) -> dict:
        """Monitor custodian compliance status for a legal hold.

        Args:
            hold_id: Unique identifier of the legal hold.

        Returns:
            Dict with compliance_fraction, pending_custodians, and overdue_custodians.
        """
        ...

    async def release_hold(
        self,
        hold_id: str,
        release_reason: str,
        releasing_attorney: str,
    ) -> dict:
        """Release a legal hold and notify custodians.

        Args:
            hold_id: Unique identifier of the hold to release.
            release_reason: Documented reason for release.
            releasing_attorney: Name of the attorney authorizing release.

        Returns:
            Updated LegalHoldRecord-compatible dict.
        """
        ...
