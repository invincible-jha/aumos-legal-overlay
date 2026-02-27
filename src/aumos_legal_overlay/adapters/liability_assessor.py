"""Liability assessor adapter for aumos-legal-overlay.

Evaluates AI-specific liability exposure across legal frameworks including
negligence, strict liability, and product liability. Produces assessment
reports with mitigation recommendations and insurance requirements.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


# AI Liability framework mapping by risk category
_AI_LIABILITY_FRAMEWORKS: dict[str, dict[str, Any]] = {
    "negligence": {
        "description": "Failure to exercise reasonable care in AI development or deployment.",
        "elements": [
            "duty_of_care", "breach_of_duty", "causation", "damages"
        ],
        "ai_specific_factors": [
            "training_data_quality", "model_validation", "human_oversight",
            "bias_testing", "performance_monitoring",
        ],
        "applicable_standards": ["ISO/IEC 42001", "NIST AI RMF", "EU AI Act Art.9"],
    },
    "strict_liability": {
        "description": "Liability without fault for abnormally dangerous AI activities.",
        "elements": ["abnormal_danger", "causation", "damages"],
        "ai_specific_factors": [
            "autonomous_decision_making", "high_stakes_domain", "irreversibility",
            "lack_of_human_review",
        ],
        "applicable_standards": ["EU AI Act Art.3(1)(a)", "CPSC Product Safety"],
    },
    "product_liability": {
        "description": "Liability for AI as a defective product causing harm.",
        "elements": ["manufacturing_defect", "design_defect", "failure_to_warn", "causation"],
        "ai_specific_factors": [
            "model_defects", "documentation_adequacy", "safety_warnings",
            "foreseeable_misuse",
        ],
        "applicable_standards": ["EU Product Liability Directive", "UCC §2-314"],
    },
}

# Risk categorization by AI domain
_AI_DOMAIN_RISK_LEVELS: dict[str, str] = {
    "medical_diagnosis": "critical",
    "autonomous_vehicles": "critical",
    "financial_lending": "high",
    "criminal_justice": "critical",
    "employment_screening": "high",
    "content_moderation": "medium",
    "customer_service_chatbot": "low",
    "product_recommendation": "low",
    "fraud_detection": "high",
    "predictive_policing": "critical",
    "facial_recognition": "high",
    "language_translation": "low",
    "document_classification": "medium",
    "manufacturing_quality": "medium",
}

# Mitigation strategies by risk level
_MITIGATION_STRATEGIES: dict[str, list[str]] = {
    "critical": [
        "Deploy mandatory human-in-the-loop review for all AI decisions.",
        "Implement adversarial testing and red-team exercises quarterly.",
        "Establish independent AI ethics board with veto authority.",
        "Maintain comprehensive model documentation (model cards) per EU AI Act.",
        "Obtain pre-deployment regulatory approval where required.",
        "Implement automatic fallback to human decision-making on uncertainty.",
        "Engage specialized AI liability insurance coverage.",
    ],
    "high": [
        "Implement human oversight for edge cases and outlier predictions.",
        "Conduct bias and fairness audits at least annually.",
        "Maintain audit logs of all AI decisions for 7+ years.",
        "Provide transparent explanations for automated decisions.",
        "Establish clear human escalation pathways.",
        "Obtain professional liability insurance with AI endorsement.",
    ],
    "medium": [
        "Monitor model drift and performance degradation monthly.",
        "Implement output confidence thresholds with fallback logic.",
        "Maintain user feedback mechanisms for AI decision appeals.",
        "Conduct annual AI risk assessments.",
        "Document intended use and known limitations.",
    ],
    "low": [
        "Log AI interactions for periodic quality review.",
        "Provide clear disclosure of AI involvement to end users.",
        "Include standard limitation of liability clause in terms of service.",
    ],
}

# Jurisdiction-specific liability rules
_JURISDICTION_LIABILITY_RULES: dict[str, dict[str, Any]] = {
    "EU": {
        "primary_framework": "EU AI Act + AI Liability Directive",
        "strict_liability_threshold": "high_risk_ai_systems",
        "compensation_available": True,
        "burden_of_proof": "reversed_for_high_risk",
        "regulatory_authority": "National Market Surveillance Authorities",
        "max_fine_percentage": 7.0,
        "notes": "High-risk AI systems require conformity assessment before deployment.",
    },
    "US": {
        "primary_framework": "Common law tort + sector-specific regulation",
        "strict_liability_threshold": "ultrahazardous_activities",
        "compensation_available": True,
        "burden_of_proof": "plaintiff_bears_burden",
        "regulatory_authority": "FTC, CFPB, sector regulators",
        "max_fine_percentage": None,
        "notes": "No comprehensive federal AI law; patchwork of state laws (CA, CO, IL).",
    },
    "UK": {
        "primary_framework": "AI Safety Institute guidelines + tort law",
        "strict_liability_threshold": "case_by_case",
        "compensation_available": True,
        "burden_of_proof": "plaintiff_bears_burden",
        "regulatory_authority": "ICO, FCA, sector regulators",
        "max_fine_percentage": 4.0,
        "notes": "Post-Brexit AI regulation diverging from EU framework.",
    },
    "US-CA": {
        "primary_framework": "California Consumer Privacy Act + CPRA + AB 2930",
        "strict_liability_threshold": "automated_decision_making",
        "compensation_available": True,
        "burden_of_proof": "shared",
        "regulatory_authority": "California Privacy Protection Agency",
        "max_fine_percentage": None,
        "notes": "AB 2930 requires ADMT impact assessments; CCPA opt-out rights apply.",
    },
}

# Insurance requirement thresholds
_INSURANCE_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "critical": {
        "minimum_coverage_usd": 50_000_000,
        "policy_types": [
            "Technology Errors & Omissions (AI endorsement)",
            "Cyber Liability (AI incident coverage)",
            "Professional Liability",
            "Product Liability",
            "Directors & Officers (AI governance)",
        ],
        "retentions": "Negotiate per-occurrence retention below $500K",
        "additional_requirements": "Insurer must accept AI-generated harm claims",
    },
    "high": {
        "minimum_coverage_usd": 10_000_000,
        "policy_types": [
            "Technology Errors & Omissions",
            "Cyber Liability",
            "Professional Liability",
        ],
        "retentions": "Standard retentions acceptable",
        "additional_requirements": "Annual attestation of AI risk controls",
    },
    "medium": {
        "minimum_coverage_usd": 2_000_000,
        "policy_types": [
            "Technology Errors & Omissions",
            "General Liability with tech endorsement",
        ],
        "retentions": "Standard retentions acceptable",
        "additional_requirements": "None beyond standard policy requirements",
    },
    "low": {
        "minimum_coverage_usd": 1_000_000,
        "policy_types": ["General Liability", "Professional Liability"],
        "retentions": "Standard retentions acceptable",
        "additional_requirements": "None",
    },
}


@dataclass
class LiabilityAssessmentReport:
    """Full AI liability assessment report.

    Attributes:
        assessment_id: Unique identifier for this assessment.
        ai_system_name: Name of the AI system being assessed.
        ai_domain: Domain of AI application.
        jurisdiction: Jurisdiction under which liability is assessed.
        risk_level: Categorized risk level (critical, high, medium, low).
        applicable_frameworks: Liability frameworks that apply.
        exposure_estimates: Estimated liability exposure by category.
        mitigation_strategies: Recommended risk mitigation actions.
        insurance_requirements: Insurance coverage recommendations.
        jurisdiction_rules: Jurisdiction-specific liability rules.
        critical_risks: Specific high-priority risk factors.
        overall_risk_score: Numeric risk score from 0.0 to 1.0.
    """

    assessment_id: str
    ai_system_name: str
    ai_domain: str
    jurisdiction: str
    risk_level: str
    applicable_frameworks: list[dict[str, Any]]
    exposure_estimates: dict[str, Any]
    mitigation_strategies: list[str]
    insurance_requirements: dict[str, Any]
    jurisdiction_rules: dict[str, Any]
    critical_risks: list[str] = field(default_factory=list)
    overall_risk_score: float = 0.0


class LiabilityAssessor:
    """Evaluates AI system liability exposure across legal frameworks.

    Applies AI-specific liability frameworks to assess negligence, strict
    liability, and product liability exposure, producing actionable risk
    reports with mitigation and insurance guidance.
    """

    def __init__(self) -> None:
        """Initialize the liability assessor."""
        logger.info("LiabilityAssessor initialized")

    def categorize_risk(
        self,
        ai_domain: str,
        is_autonomous: bool,
        high_stakes_decisions: bool,
        human_oversight: bool,
    ) -> str:
        """Categorize the risk level of an AI system.

        Args:
            ai_domain: Domain of AI application.
            is_autonomous: Whether the AI makes autonomous decisions without review.
            high_stakes_decisions: Whether decisions have significant real-world impact.
            human_oversight: Whether human oversight is implemented.

        Returns:
            Risk level string: "critical", "high", "medium", or "low".
        """
        base_risk = _AI_DOMAIN_RISK_LEVELS.get(ai_domain, "medium")

        risk_order = ["low", "medium", "high", "critical"]
        risk_index = risk_order.index(base_risk)

        # Escalate risk for autonomous high-stakes systems without oversight
        if is_autonomous and high_stakes_decisions:
            risk_index = min(3, risk_index + 1)
        if not human_oversight and base_risk in ("high", "critical"):
            risk_index = min(3, risk_index + 1)

        return risk_order[risk_index]

    def estimate_exposure(
        self,
        risk_level: str,
        revenue_at_risk_usd: float,
        affected_users_estimate: int,
        regulatory_jurisdiction: str,
    ) -> dict[str, Any]:
        """Estimate liability exposure across categories.

        Args:
            risk_level: Risk level (critical, high, medium, low).
            revenue_at_risk_usd: Annual revenue dependent on the AI system.
            affected_users_estimate: Estimated number of affected users.
            regulatory_jurisdiction: Jurisdiction for regulatory penalty calculation.

        Returns:
            Dict with exposure estimates by category and total potential exposure.
        """
        # Regulatory fine estimates
        jur_rules = _JURISDICTION_LIABILITY_RULES.get(
            regulatory_jurisdiction,
            _JURISDICTION_LIABILITY_RULES["US"]
        )
        max_fine_pct = jur_rules.get("max_fine_percentage") or 0.0
        regulatory_fine_estimate = revenue_at_risk_usd * (max_fine_pct / 100.0)

        # Class action exposure: $1K-$10K per affected user depending on risk
        per_user_multiplier = {
            "critical": 10000,
            "high": 3000,
            "medium": 500,
            "low": 100,
        }.get(risk_level, 500)
        class_action_exposure = affected_users_estimate * per_user_multiplier

        # Reputational exposure (estimated brand value impact)
        reputational_exposure = revenue_at_risk_usd * {
            "critical": 2.0,
            "high": 0.5,
            "medium": 0.1,
            "low": 0.02,
        }.get(risk_level, 0.1)

        # Remediation costs
        remediation_cost = revenue_at_risk_usd * {
            "critical": 0.3,
            "high": 0.1,
            "medium": 0.03,
            "low": 0.005,
        }.get(risk_level, 0.03)

        total_exposure = (
            regulatory_fine_estimate
            + class_action_exposure
            + reputational_exposure
            + remediation_cost
        )

        return {
            "regulatory_fine_estimate_usd": round(regulatory_fine_estimate),
            "class_action_exposure_usd": round(class_action_exposure),
            "reputational_exposure_usd": round(reputational_exposure),
            "remediation_cost_usd": round(remediation_cost),
            "total_potential_exposure_usd": round(total_exposure),
            "per_user_exposure_usd": per_user_multiplier,
            "notes": (
                f"Estimates based on {regulatory_jurisdiction} regulatory framework. "
                f"Regulatory fine calculated at {max_fine_pct}% of revenue."
                if max_fine_pct
                else "Regulatory fines vary; consult legal counsel for precise estimates."
            ),
        }

    def compute_risk_score(
        self,
        risk_level: str,
        frameworks_triggered: int,
        missing_controls: int,
        jurisdiction: str,
    ) -> float:
        """Compute a normalized overall risk score.

        Args:
            risk_level: Base risk level.
            frameworks_triggered: Number of liability frameworks applicable.
            missing_controls: Number of missing required controls.
            jurisdiction: Jurisdiction for regulatory weight adjustment.

        Returns:
            Normalized risk score from 0.0 (minimal) to 1.0 (critical).
        """
        base_scores = {"critical": 0.85, "high": 0.65, "medium": 0.40, "low": 0.15}
        score = base_scores.get(risk_level, 0.40)

        # Increase for each additional liability framework
        score += frameworks_triggered * 0.03
        score += missing_controls * 0.05

        # EU and CA jurisdictions carry higher regulatory risk
        if jurisdiction in ("EU", "US-CA"):
            score = min(1.0, score + 0.05)

        return round(min(1.0, score), 3)

    def assess(
        self,
        ai_system_name: str,
        ai_domain: str,
        jurisdiction: str,
        is_autonomous: bool = False,
        high_stakes_decisions: bool = False,
        human_oversight: bool = True,
        revenue_at_risk_usd: float = 0.0,
        affected_users_estimate: int = 0,
        missing_controls: list[str] | None = None,
    ) -> LiabilityAssessmentReport:
        """Perform a comprehensive AI liability assessment.

        Args:
            ai_system_name: Name of the AI system being assessed.
            ai_domain: AI domain (e.g., "medical_diagnosis", "fraud_detection").
            jurisdiction: Jurisdiction code (EU, US, US-CA, US-NY, UK).
            is_autonomous: Whether the AI operates autonomously.
            high_stakes_decisions: Whether decisions have significant real-world impact.
            human_oversight: Whether human oversight is implemented.
            revenue_at_risk_usd: Annual revenue at risk if system fails.
            affected_users_estimate: Estimated user population affected.
            missing_controls: Known missing risk controls.

        Returns:
            LiabilityAssessmentReport with full risk analysis.
        """
        assessment_id = str(uuid.uuid4())
        missing_controls = missing_controls or []

        logger.info(
            "Running liability assessment",
            assessment_id=assessment_id,
            ai_system_name=ai_system_name,
            ai_domain=ai_domain,
            jurisdiction=jurisdiction,
        )

        risk_level = self.categorize_risk(
            ai_domain=ai_domain,
            is_autonomous=is_autonomous,
            high_stakes_decisions=high_stakes_decisions,
            human_oversight=human_oversight,
        )

        # Determine applicable frameworks
        applicable_frameworks: list[dict[str, Any]] = []
        for framework_name, framework in _AI_LIABILITY_FRAMEWORKS.items():
            triggers = []
            if framework_name == "negligence":
                triggers = [f for f in framework["ai_specific_factors"] if f in missing_controls]
            elif framework_name == "strict_liability" and (is_autonomous and risk_level in ("critical", "high")):
                triggers = framework["ai_specific_factors"]
            elif framework_name == "product_liability" and high_stakes_decisions:
                triggers = framework["ai_specific_factors"]

            applicable_frameworks.append({
                "framework": framework_name,
                "description": framework["description"],
                "is_triggered": len(triggers) > 0 or framework_name == "negligence",
                "triggered_factors": triggers,
                "applicable_standards": framework["applicable_standards"],
            })

        triggered_count = sum(1 for f in applicable_frameworks if f["is_triggered"])

        exposure_estimates = self.estimate_exposure(
            risk_level=risk_level,
            revenue_at_risk_usd=revenue_at_risk_usd,
            affected_users_estimate=affected_users_estimate,
            regulatory_jurisdiction=jurisdiction,
        )

        mitigation_strategies = _MITIGATION_STRATEGIES.get(risk_level, [])
        insurance_requirements = _INSURANCE_REQUIREMENTS.get(risk_level, _INSURANCE_REQUIREMENTS["medium"])
        jurisdiction_rules = _JURISDICTION_LIABILITY_RULES.get(jurisdiction, _JURISDICTION_LIABILITY_RULES["US"])

        critical_risks: list[str] = []
        if not human_oversight and risk_level in ("critical", "high"):
            critical_risks.append("No human oversight on high-risk AI decisions — strict liability risk elevated.")
        if is_autonomous and jurisdiction == "EU":
            critical_risks.append("Autonomous AI in EU likely qualifies as 'high-risk' under EU AI Act Art.6.")
        for control in missing_controls:
            critical_risks.append(f"Missing control: {control}")

        overall_risk_score = self.compute_risk_score(
            risk_level=risk_level,
            frameworks_triggered=triggered_count,
            missing_controls=len(missing_controls),
            jurisdiction=jurisdiction,
        )

        report = LiabilityAssessmentReport(
            assessment_id=assessment_id,
            ai_system_name=ai_system_name,
            ai_domain=ai_domain,
            jurisdiction=jurisdiction,
            risk_level=risk_level,
            applicable_frameworks=applicable_frameworks,
            exposure_estimates=exposure_estimates,
            mitigation_strategies=mitigation_strategies,
            insurance_requirements=insurance_requirements,
            jurisdiction_rules=jurisdiction_rules,
            critical_risks=critical_risks,
            overall_risk_score=overall_risk_score,
        )

        logger.info(
            "Liability assessment complete",
            assessment_id=assessment_id,
            risk_level=risk_level,
            overall_risk_score=overall_risk_score,
            frameworks_triggered=triggered_count,
        )
        return report

    def export_as_dict(self, report: LiabilityAssessmentReport) -> dict[str, Any]:
        """Serialize an assessment report to a plain dict.

        Args:
            report: The LiabilityAssessmentReport to serialize.

        Returns:
            Plain dict representation for JSON serialization.
        """
        return {
            "assessment_id": report.assessment_id,
            "ai_system_name": report.ai_system_name,
            "ai_domain": report.ai_domain,
            "jurisdiction": report.jurisdiction,
            "risk_level": report.risk_level,
            "overall_risk_score": report.overall_risk_score,
            "applicable_frameworks": report.applicable_frameworks,
            "exposure_estimates": report.exposure_estimates,
            "mitigation_strategies": report.mitigation_strategies,
            "insurance_requirements": report.insurance_requirements,
            "jurisdiction_rules": report.jurisdiction_rules,
            "critical_risks": report.critical_risks,
        }


__all__ = ["LiabilityAssessor", "LiabilityAssessmentReport"]
