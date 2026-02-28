"""EDRM (Electronic Discovery Reference Model) workflow management.

GAP-318: EDRM Compliance.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class EDRMStage(str, Enum):
    """EDRM stages in sequential order.

    Stages must be traversed in order — cannot skip Preservation before Collection.
    Reference: Electronic Discovery Reference Model v3.0 (EDRM.net).
    """

    IDENTIFICATION = "identification"
    PRESERVATION = "preservation"
    COLLECTION = "collection"
    PROCESSING = "processing"
    REVIEW = "review"
    ANALYSIS = "analysis"
    PRODUCTION = "production"
    PRESENTATION = "presentation"


# Required predecessor stage for each stage transition
STAGE_PREREQUISITES: dict[EDRMStage, EDRMStage | None] = {
    EDRMStage.IDENTIFICATION: None,
    EDRMStage.PRESERVATION: EDRMStage.IDENTIFICATION,
    EDRMStage.COLLECTION: EDRMStage.PRESERVATION,
    EDRMStage.PROCESSING: EDRMStage.COLLECTION,
    EDRMStage.REVIEW: EDRMStage.PROCESSING,
    EDRMStage.ANALYSIS: EDRMStage.REVIEW,
    EDRMStage.PRODUCTION: EDRMStage.ANALYSIS,
    EDRMStage.PRESENTATION: EDRMStage.PRODUCTION,
}

STAGE_ORDER: list[EDRMStage] = [
    EDRMStage.IDENTIFICATION,
    EDRMStage.PRESERVATION,
    EDRMStage.COLLECTION,
    EDRMStage.PROCESSING,
    EDRMStage.REVIEW,
    EDRMStage.ANALYSIS,
    EDRMStage.PRODUCTION,
    EDRMStage.PRESENTATION,
]


@dataclass
class EDRMStageRecord:
    """Record of an EDRM stage completion."""

    stage: EDRMStage
    completed_at: datetime
    completed_by: str
    document_count: int
    notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EDRMWorkflow:
    """An active EDRM workflow for a litigation matter.

    Tracks progress through all 8 EDRM stages with validation
    that stages are completed in the correct sequential order.
    """

    workflow_id: str
    case_name: str
    case_number: str
    matter_type: str  # litigation, investigation, regulatory, arbitration
    tenant_id: str
    current_stage: EDRMStage = EDRMStage.IDENTIFICATION
    stages_completed: list[EDRMStageRecord] = field(default_factory=list)
    status: str = "active"  # active | completed | suspended
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    total_documents: int = 0
    produced_documents: int = 0


class EDRMWorkflowService:
    """Manages EDRM-compliant e-discovery workflows.

    Enforces the Electronic Discovery Reference Model stage ordering.
    Stages must be completed sequentially — cannot advance to Collection
    before completing Preservation, etc.

    Reference: EDRM.net v3.0 model, adopted by Sedona Conference and ILTA.
    """

    def create_workflow(
        self,
        workflow_id: str,
        case_name: str,
        case_number: str,
        matter_type: str,
        tenant_id: str,
    ) -> EDRMWorkflow:
        """Create a new EDRM workflow for a litigation matter.

        Args:
            workflow_id: Unique workflow identifier (UUID).
            case_name: Human-readable case name.
            case_number: Court-assigned case number.
            matter_type: Type of legal matter (litigation, investigation, etc.).
            tenant_id: Tenant scope for multi-tenant isolation.

        Returns:
            New EDRMWorkflow starting at IDENTIFICATION stage.
        """
        workflow = EDRMWorkflow(
            workflow_id=workflow_id,
            case_name=case_name,
            case_number=case_number,
            matter_type=matter_type,
            tenant_id=tenant_id,
        )
        logger.info(
            "edrm_workflow_created",
            workflow_id=workflow_id,
            case_name=case_name,
            case_number=case_number,
        )
        return workflow

    def advance_stage(
        self,
        workflow: EDRMWorkflow,
        stage: EDRMStage,
        completed_by: str,
        document_count: int,
        notes: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> EDRMWorkflow:
        """Advance workflow to the next EDRM stage.

        Args:
            workflow: The active EDRM workflow.
            stage: The stage being completed.
            completed_by: User ID of the attorney or paralegal completing the stage.
            document_count: Number of documents processed in this stage.
            notes: Optional notes for the stage completion record.
            metadata: Optional stage-specific metadata.

        Returns:
            Updated EDRMWorkflow with the stage recorded.

        Raises:
            ValueError: If the stage transition is invalid (out of order or already completed).
        """
        self._validate_transition(workflow, stage)

        stage_record = EDRMStageRecord(
            stage=stage,
            completed_at=datetime.now(timezone.utc),
            completed_by=completed_by,
            document_count=document_count,
            notes=notes,
            metadata=metadata or {},
        )
        workflow.stages_completed.append(stage_record)
        workflow.total_documents = max(workflow.total_documents, document_count)

        # Advance current_stage to the next stage in sequence
        current_index = STAGE_ORDER.index(stage)
        if current_index < len(STAGE_ORDER) - 1:
            workflow.current_stage = STAGE_ORDER[current_index + 1]
        else:
            workflow.status = "completed"

        if stage == EDRMStage.PRODUCTION:
            workflow.produced_documents = document_count

        workflow.updated_at = datetime.now(timezone.utc)

        logger.info(
            "edrm_stage_advanced",
            workflow_id=workflow.workflow_id,
            stage=stage.value,
            completed_by=completed_by,
            document_count=document_count,
        )
        return workflow

    def get_stage_summary(self, workflow: EDRMWorkflow) -> dict[str, Any]:
        """Get a summary of stage completion status for a workflow.

        Args:
            workflow: The EDRM workflow to summarize.

        Returns:
            Dict with stage completion status and statistics.
        """
        completed_stages = {r.stage.value for r in workflow.stages_completed}
        return {
            "workflow_id": workflow.workflow_id,
            "case_name": workflow.case_name,
            "case_number": workflow.case_number,
            "current_stage": workflow.current_stage.value,
            "status": workflow.status,
            "stages_completed": [
                {
                    "stage": r.stage.value,
                    "completed_at": r.completed_at.isoformat(),
                    "completed_by": r.completed_by,
                    "document_count": r.document_count,
                }
                for r in workflow.stages_completed
            ],
            "stages_pending": [
                s.value
                for s in STAGE_ORDER
                if s.value not in completed_stages
            ],
            "total_stages": len(STAGE_ORDER),
            "completed_count": len(workflow.stages_completed),
            "total_documents": workflow.total_documents,
            "produced_documents": workflow.produced_documents,
        }

    def _validate_transition(self, workflow: EDRMWorkflow, stage: EDRMStage) -> None:
        """Validate that a stage transition is legal per EDRM ordering.

        Args:
            workflow: Current workflow state.
            stage: Proposed next stage.

        Raises:
            ValueError: If transition violates EDRM sequential ordering.
        """
        if workflow.status == "completed":
            raise ValueError(
                f"Workflow {workflow.workflow_id} is already completed. Cannot advance stage."
            )

        completed_stages = {r.stage for r in workflow.stages_completed}
        if stage in completed_stages:
            raise ValueError(
                f"Stage {stage.value} has already been completed for workflow {workflow.workflow_id}."
            )

        prerequisite = STAGE_PREREQUISITES[stage]
        if prerequisite is not None and prerequisite not in completed_stages:
            raise ValueError(
                f"Cannot advance to {stage.value} before completing {prerequisite.value}. "
                f"EDRM requires sequential stage completion."
            )
