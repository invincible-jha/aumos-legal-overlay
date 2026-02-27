"""IP protector adapter for aumos-legal-overlay.

Tracks intellectual property assets including patents, trademarks, copyrights,
and trade secrets. Assesses infringement risk, manages clearance workflows,
and generates IP portfolio reports.
"""

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


# IP asset type definitions
_IP_ASSET_TYPES: dict[str, dict[str, Any]] = {
    "patent": {
        "description": "Granted or pending patent rights",
        "registration_required": True,
        "registrar": "USPTO / EPO / WIPO",
        "protection_term_years": 20,
        "enforcement_mechanism": "Infringement lawsuit, ITC complaint",
    },
    "trademark": {
        "description": "Brand identifiers including marks, logos, trade dress",
        "registration_required": False,  # Common law rights exist
        "registrar": "USPTO",
        "protection_term_years": None,  # Perpetual with use
        "enforcement_mechanism": "Cease-and-desist, infringement suit, UDRP",
    },
    "copyright": {
        "description": "Creative and software works (code, documentation, data)",
        "registration_required": False,  # Automatic, but registration strengthens claims
        "registrar": "USCO",
        "protection_term_years": 95,  # Work for hire
        "enforcement_mechanism": "DMCA takedown, infringement lawsuit",
    },
    "trade_secret": {
        "description": "Proprietary information, ML models, training data, processes",
        "registration_required": False,
        "registrar": None,
        "protection_term_years": None,  # Perpetual while secret maintained
        "enforcement_mechanism": "DTSA claim, misappropriation suit, injunction",
    },
}

# Training data IP risk factors
_TRAINING_DATA_RISK_FACTORS: dict[str, str] = {
    "scraped_web": "high",
    "licensed_dataset": "low",
    "synthetic_data": "minimal",
    "proprietary_corpus": "medium",
    "open_source_dataset": "low",
    "user_generated_content": "high",
    "third_party_api": "medium",
    "purchased_dataset": "low",
    "government_data": "minimal",
}

# Infringement risk assessment by scenario
_INFRINGEMENT_SCENARIOS: dict[str, dict[str, Any]] = {
    "model_replication": {
        "description": "AI model replicates copyrighted training data verbatim.",
        "risk_level": "critical",
        "applicable_law": ["17 U.S.C. §106", "EU Copyright Directive Art.4"],
        "mitigation": "Implement memorization detection and output filtering.",
    },
    "trademark_confusion": {
        "description": "AI output generates content likely to cause brand confusion.",
        "risk_level": "high",
        "applicable_law": ["15 U.S.C. §1114", "TDRA §43(c)"],
        "mitigation": "Implement trademark keyword filtering in model outputs.",
    },
    "patent_infringement": {
        "description": "AI system practices a patented method without license.",
        "risk_level": "high",
        "applicable_law": ["35 U.S.C. §271", "EU Patent Convention Art.69"],
        "mitigation": "Conduct freedom-to-operate (FTO) analysis before deployment.",
    },
    "trade_secret_misappropriation": {
        "description": "AI trained on improperly obtained proprietary data.",
        "risk_level": "critical",
        "applicable_law": ["18 U.S.C. §1832 (DTSA)", "EU Trade Secrets Directive"],
        "mitigation": "Audit training data provenance; destroy misappropriated data.",
    },
    "fair_use_boundary": {
        "description": "AI use of copyrighted content tests fair use doctrine limits.",
        "risk_level": "medium",
        "applicable_law": ["17 U.S.C. §107"],
        "mitigation": "Document transformative use; minimize amount reproduced.",
    },
}


@dataclass
class IPAsset:
    """Representation of a tracked IP asset.

    Attributes:
        asset_id: Unique identifier for this IP asset.
        asset_type: Type of IP (patent, trademark, copyright, trade_secret).
        asset_name: Human-readable name or title.
        owner: Owner entity name.
        registration_number: Registration or application number if applicable.
        registration_date: Date of registration or application filing.
        expiration_date: Expiration date if applicable.
        jurisdiction: Jurisdiction(s) of protection.
        status: Asset status (active, pending, expired, abandoned).
        description: Detailed description of protected subject matter.
        ai_related: Whether this asset relates to AI/ML systems.
        training_data_source: Source of training data if applicable.
        metadata: Additional asset metadata.
    """

    asset_id: str
    asset_type: str
    asset_name: str
    owner: str
    registration_number: str | None
    registration_date: date | None
    expiration_date: date | None
    jurisdiction: list[str]
    status: str
    description: str
    ai_related: bool
    training_data_source: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class InfringementRiskAssessment:
    """Assessment of IP infringement risk for an AI asset.

    Attributes:
        assessment_id: Unique identifier for this assessment.
        asset_id: IP asset being assessed.
        overall_risk_level: Aggregate risk level.
        scenario_assessments: Risk assessment per identified scenario.
        affected_ip_types: IP types with identified risk.
        prior_art_conflicts: Known prior art that may affect validity.
        clearance_actions_required: Actions needed before deployment.
        estimated_litigation_risk_usd: Estimated litigation exposure.
    """

    assessment_id: str
    asset_id: str
    overall_risk_level: str
    scenario_assessments: list[dict[str, Any]]
    affected_ip_types: list[str]
    prior_art_conflicts: list[dict[str, str]]
    clearance_actions_required: list[str]
    estimated_litigation_risk_usd: float


class IPProtector:
    """Tracks and protects intellectual property assets for legal compliance.

    Maintains an IP asset registry, evaluates infringement risk, manages
    clearance workflows, integrates with prior art databases, and produces
    IP portfolio reports.
    """

    def __init__(self, tenant_id: str) -> None:
        """Initialize the IP protector for a specific tenant.

        Args:
            tenant_id: Tenant identifier for asset scoping.
        """
        self._tenant_id = tenant_id
        self._asset_registry: dict[str, IPAsset] = {}
        logger.info("IPProtector initialized", tenant_id=tenant_id)

    def register_asset(
        self,
        asset_type: str,
        asset_name: str,
        owner: str,
        description: str,
        jurisdiction: list[str],
        registration_number: str | None = None,
        registration_date: date | None = None,
        protection_term_years: int | None = None,
        ai_related: bool = False,
        training_data_source: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IPAsset:
        """Register a new IP asset in the registry.

        Args:
            asset_type: IP asset type (patent, trademark, copyright, trade_secret).
            asset_name: Name or title of the IP asset.
            owner: Owning entity name.
            description: Description of the protected subject matter.
            jurisdiction: List of jurisdiction codes where protection applies.
            registration_number: Registration or application number.
            registration_date: Date of registration or filing.
            protection_term_years: Protection term; auto-set from type if None.
            ai_related: Whether this asset relates to AI/ML.
            training_data_source: Training data source type if applicable.
            metadata: Additional metadata dict.

        Returns:
            Registered IPAsset.

        Raises:
            ValueError: If asset_type is not recognized.
        """
        if asset_type not in _IP_ASSET_TYPES:
            raise ValueError(
                f"Unknown asset_type '{asset_type}'. "
                f"Supported: {list(_IP_ASSET_TYPES.keys())}"
            )

        asset_id = str(uuid.uuid4())
        type_info = _IP_ASSET_TYPES[asset_type]
        term_years = protection_term_years or type_info.get("protection_term_years")

        expiration_date: date | None = None
        if registration_date and term_years:
            expiration_date = registration_date + timedelta(days=term_years * 365)

        asset = IPAsset(
            asset_id=asset_id,
            asset_type=asset_type,
            asset_name=asset_name,
            owner=owner,
            registration_number=registration_number,
            registration_date=registration_date,
            expiration_date=expiration_date,
            jurisdiction=jurisdiction,
            status="active" if registration_number else "pending",
            description=description,
            ai_related=ai_related,
            training_data_source=training_data_source,
            metadata=metadata or {},
        )
        self._asset_registry[asset_id] = asset

        logger.info(
            "IP asset registered",
            asset_id=asset_id,
            asset_type=asset_type,
            asset_name=asset_name,
            tenant_id=self._tenant_id,
        )
        return asset

    def classify_model_ip(
        self,
        model_name: str,
        training_data_sources: list[str],
        architecture_type: str,
        has_novel_architecture: bool,
    ) -> dict[str, Any]:
        """Classify IP status of an AI model.

        Determines applicable IP categories (patent, copyright, trade_secret)
        and associated risk levels based on model characteristics.

        Args:
            model_name: Name of the AI model.
            training_data_sources: List of training data source types.
            architecture_type: Model architecture (transformer, CNN, etc.).
            has_novel_architecture: Whether architecture is potentially patentable.

        Returns:
            Dict with ip_classification, applicable_protections, risk_factors.
        """
        applicable_protections: list[dict[str, str]] = []
        risk_factors: list[str] = []

        # Model weights can be protected as trade secrets
        applicable_protections.append({
            "ip_type": "trade_secret",
            "scope": "Model weights, hyperparameters, training configuration",
            "strength": "high" if len(training_data_sources) == 1 else "medium",
        })

        # Code and architecture may have copyright
        applicable_protections.append({
            "ip_type": "copyright",
            "scope": f"Model architecture code for {architecture_type}",
            "strength": "medium",
        })

        # Novel architecture may be patentable
        if has_novel_architecture:
            applicable_protections.append({
                "ip_type": "patent",
                "scope": f"Novel {architecture_type} architecture or training method",
                "strength": "potential — requires patent search and application",
            })

        # Assess training data risk
        for source in training_data_sources:
            risk = _TRAINING_DATA_RISK_FACTORS.get(source, "medium")
            if risk in ("high", "critical"):
                risk_factors.append(
                    f"Training data source '{source}' carries {risk} IP infringement risk."
                )

        logger.info(
            "Model IP classified",
            model_name=model_name,
            protection_count=len(applicable_protections),
            risk_factor_count=len(risk_factors),
        )

        return {
            "model_name": model_name,
            "ip_classification": applicable_protections,
            "risk_factors": risk_factors,
            "training_data_risk": {
                source: _TRAINING_DATA_RISK_FACTORS.get(source, "medium")
                for source in training_data_sources
            },
            "recommended_actions": [
                "Register copyright for original model code.",
                "File trade secret protocols for model weights (access controls, NDAs).",
                "Conduct FTO analysis before deployment." if has_novel_architecture else "Document architecture provenance.",
            ],
        }

    def assess_infringement_risk(
        self,
        asset_id: str,
        use_cases: list[str],
        training_data_sources: list[str],
        deployment_jurisdictions: list[str],
    ) -> InfringementRiskAssessment:
        """Assess infringement risk for a registered IP asset.

        Args:
            asset_id: ID of the registered IP asset.
            use_cases: Intended deployment use cases.
            training_data_sources: Data sources used to train the AI.
            deployment_jurisdictions: Jurisdictions for deployment.

        Returns:
            InfringementRiskAssessment with risk details and clearance actions.

        Raises:
            KeyError: If asset_id is not found in registry.
        """
        if asset_id not in self._asset_registry:
            raise KeyError(f"IP asset '{asset_id}' not found in registry.")

        assessment_id = str(uuid.uuid4())
        scenario_assessments: list[dict[str, Any]] = []
        risk_levels: list[str] = []
        clearance_actions: list[str] = []
        prior_art_conflicts: list[dict[str, str]] = []

        # Check training data scenarios
        for source in training_data_sources:
            source_risk = _TRAINING_DATA_RISK_FACTORS.get(source, "medium")
            if source_risk in ("high", "critical"):
                scenario = _INFRINGEMENT_SCENARIOS["trade_secret_misappropriation"]
                scenario_assessments.append({
                    "scenario": "trade_secret_misappropriation",
                    "triggered_by": f"training_data_source: {source}",
                    "risk_level": "high" if source_risk == "high" else "critical",
                    "mitigation": scenario["mitigation"],
                    "applicable_law": scenario["applicable_law"],
                })
                clearance_actions.append(
                    f"Audit provenance of '{source}' training data; obtain written license."
                )
                risk_levels.append("high")

        # Check model output scenarios
        if "model_replication" in use_cases or any("output" in u for u in use_cases):
            scenario = _INFRINGEMENT_SCENARIOS["model_replication"]
            scenario_assessments.append({
                "scenario": "model_replication",
                "triggered_by": "generative AI output use case",
                "risk_level": scenario["risk_level"],
                "mitigation": scenario["mitigation"],
                "applicable_law": scenario["applicable_law"],
            })
            clearance_actions.append(scenario["mitigation"])
            risk_levels.append(scenario["risk_level"])

        # Check patent use case
        if any("patented_method" in u for u in use_cases):
            scenario = _INFRINGEMENT_SCENARIOS["patent_infringement"]
            scenario_assessments.append({
                "scenario": "patent_infringement",
                "triggered_by": "use case involves patented method",
                "risk_level": scenario["risk_level"],
                "mitigation": scenario["mitigation"],
                "applicable_law": scenario["applicable_law"],
            })
            clearance_actions.append("Commission freedom-to-operate (FTO) patent search.")
            risk_levels.append("high")
            prior_art_conflicts.append({
                "source": "USPTO Patent Database",
                "conflict_type": "potential_infringement",
                "action_required": "FTO analysis required",
            })

        # Aggregate risk level
        risk_order = ["minimal", "low", "medium", "high", "critical"]
        highest_risk = max(risk_levels, key=lambda r: risk_order.index(r) if r in risk_order else 0) if risk_levels else "low"

        # Estimate litigation risk
        risk_multiplier = {"critical": 5_000_000, "high": 1_000_000, "medium": 200_000, "low": 50_000, "minimal": 10_000}
        litigation_risk = risk_multiplier.get(highest_risk, 200_000) * len(deployment_jurisdictions)

        affected_ip_types = list({
            sc["scenario"].split("_")[0] for sc in scenario_assessments
        })

        assessment = InfringementRiskAssessment(
            assessment_id=assessment_id,
            asset_id=asset_id,
            overall_risk_level=highest_risk,
            scenario_assessments=scenario_assessments,
            affected_ip_types=affected_ip_types,
            prior_art_conflicts=prior_art_conflicts,
            clearance_actions_required=clearance_actions,
            estimated_litigation_risk_usd=litigation_risk,
        )

        logger.info(
            "Infringement risk assessment complete",
            assessment_id=assessment_id,
            asset_id=asset_id,
            risk_level=highest_risk,
            scenario_count=len(scenario_assessments),
        )
        return assessment

    def generate_portfolio_report(self) -> dict[str, Any]:
        """Generate an IP portfolio report for the tenant.

        Returns:
            Dict with portfolio summary, asset breakdown, and expiring assets.
        """
        now = datetime.now(tz=timezone.utc).date()
        assets = list(self._asset_registry.values())

        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        expiring_soon: list[dict[str, Any]] = []
        ai_related_count = 0

        for asset in assets:
            by_type[asset.asset_type] = by_type.get(asset.asset_type, 0) + 1
            by_status[asset.status] = by_status.get(asset.status, 0) + 1
            if asset.ai_related:
                ai_related_count += 1
            if asset.expiration_date:
                days_until_expiry = (asset.expiration_date - now).days
                if 0 <= days_until_expiry <= 365:
                    expiring_soon.append({
                        "asset_id": asset.asset_id,
                        "asset_name": asset.asset_name,
                        "asset_type": asset.asset_type,
                        "expiration_date": asset.expiration_date.isoformat(),
                        "days_until_expiry": days_until_expiry,
                    })

        report = {
            "tenant_id": self._tenant_id,
            "report_generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "total_assets": len(assets),
            "ai_related_assets": ai_related_count,
            "assets_by_type": by_type,
            "assets_by_status": by_status,
            "expiring_within_12_months": sorted(expiring_soon, key=lambda a: a["days_until_expiry"]),
            "top_jurisdictions": self._compute_top_jurisdictions(assets),
        }

        logger.info(
            "IP portfolio report generated",
            tenant_id=self._tenant_id,
            total_assets=len(assets),
            ai_related_count=ai_related_count,
        )
        return report

    def _compute_top_jurisdictions(self, assets: list[IPAsset]) -> list[dict[str, Any]]:
        """Compute jurisdiction coverage counts across assets.

        Args:
            assets: List of registered IP assets.

        Returns:
            List of jurisdiction dicts sorted by asset count descending.
        """
        jur_counts: dict[str, int] = {}
        for asset in assets:
            for jur in asset.jurisdiction:
                jur_counts[jur] = jur_counts.get(jur, 0) + 1
        return [
            {"jurisdiction": jur, "asset_count": count}
            for jur, count in sorted(jur_counts.items(), key=lambda x: x[1], reverse=True)
        ][:10]

    def run_clearance_workflow(
        self,
        proposed_asset_name: str,
        proposed_asset_type: str,
        jurisdiction: str,
    ) -> dict[str, Any]:
        """Run an IP clearance workflow for a proposed new asset.

        Checks for potential conflicts with existing registry entries and
        produces a clearance checklist.

        Args:
            proposed_asset_name: Name of the proposed asset.
            proposed_asset_type: Type of proposed asset.
            jurisdiction: Target jurisdiction for clearance.

        Returns:
            Dict with clearance_status, conflicts_found, and required_steps.
        """
        workflow_id = str(uuid.uuid4())
        conflicts: list[dict[str, str]] = []

        # Simple name similarity check against existing registry
        name_hash = hashlib.sha256(proposed_asset_name.lower().encode()).hexdigest()[:8]
        for asset in self._asset_registry.values():
            if (
                asset.asset_type == proposed_asset_type
                and jurisdiction in asset.jurisdiction
                and asset.asset_name.lower() in proposed_asset_name.lower()
            ):
                conflicts.append({
                    "conflicting_asset_id": asset.asset_id,
                    "conflicting_asset_name": asset.asset_name,
                    "conflict_type": "name_similarity",
                    "jurisdiction": jurisdiction,
                })

        required_steps = [
            f"Search {_IP_ASSET_TYPES[proposed_asset_type]['registrar'] or 'relevant databases'} for '{proposed_asset_name}'.",
            "Conduct knockout search for phonetically similar names (trademark)." if proposed_asset_type == "trademark" else "",
            "Review prior art databases (USPTO, Google Patents)." if proposed_asset_type == "patent" else "",
            "Consult IP counsel for clearance opinion.",
            "File application upon clearance confirmation.",
        ]
        required_steps = [s for s in required_steps if s]

        clearance_status = "blocked" if conflicts else "clear_pending_search"

        logger.info(
            "IP clearance workflow complete",
            workflow_id=workflow_id,
            proposed_asset_name=proposed_asset_name,
            clearance_status=clearance_status,
            conflict_count=len(conflicts),
        )

        return {
            "workflow_id": workflow_id,
            "proposed_asset_name": proposed_asset_name,
            "proposed_asset_type": proposed_asset_type,
            "jurisdiction": jurisdiction,
            "clearance_status": clearance_status,
            "conflicts_found": conflicts,
            "required_steps": required_steps,
            "name_hash": name_hash,
        }


__all__ = ["IPProtector", "IPAsset", "InfringementRiskAssessment"]
