"""Clause validator adapter for aumos-legal-overlay.

Performs compliance checking of contract clauses against regulatory frameworks,
identifies missing required clauses, detects conflicts, and generates validation reports.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


# Clause-to-regulation mapping: clause_type -> list of regulations requiring it
_CLAUSE_REGULATION_MAP: dict[str, list[str]] = {
    "data_processing": ["GDPR Art.28", "CCPA §1798.100", "HIPAA §164.504"],
    "data_breach_notification": ["GDPR Art.33", "CCPA §1798.150", "HIPAA §164.400"],
    "right_to_erasure": ["GDPR Art.17", "CCPA §1798.105"],
    "data_portability": ["GDPR Art.20", "CCPA §1798.100"],
    "limitation_of_liability": ["UCC §2-719", "SOX §301"],
    "indemnification": ["FAR 52.228-7", "ISO 27001 A.18"],
    "audit_rights": ["SOX §404", "PCI-DSS Req.12.8", "ISO 27001 A.18.2"],
    "confidentiality": ["HIPAA §164.530", "SOC2 CC9.2", "GDPR Art.28(3)(b)"],
    "intellectual_property": ["35 U.S.C. §261", "17 U.S.C. §101"],
    "governing_law": ["FRCP 8(a)", "UCC §1-301"],
    "dispute_resolution": ["FAA §2", "UNCITRAL Model Law Art.7"],
    "force_majeure": ["UCC §2-615", "CISG Art.79"],
    "insurance": ["FAR 28.301", "ISO 27001 A.6.1"],
    "anti_bribery": ["FCPA §30A", "UK Bribery Act 2010 S.7"],
    "export_controls": ["EAR §730", "ITAR §120.1"],
    "non_discrimination": ["Title VII §703", "ADA §102", "ADEA §4"],
}

# Required clauses by contract type
_REQUIRED_CLAUSES_BY_TYPE: dict[str, list[str]] = {
    "NDA": ["confidentiality", "governing_law", "limitation_of_liability"],
    "MSA": [
        "confidentiality", "intellectual_property", "limitation_of_liability",
        "indemnification", "governing_law", "dispute_resolution",
    ],
    "SLA": ["limitation_of_liability", "governing_law"],
    "EMPLOYMENT": [
        "confidentiality", "non_discrimination", "intellectual_property", "governing_law",
    ],
    "DATA_PROCESSING": [
        "data_processing", "data_breach_notification", "audit_rights",
        "confidentiality", "data_portability",
    ],
    "VENDOR": [
        "limitation_of_liability", "indemnification", "governing_law",
        "insurance", "confidentiality",
    ],
}

# Clause conflict pairs: (clause_a, clause_b, conflict_description)
_CLAUSE_CONFLICT_PAIRS: list[tuple[str, str, str]] = [
    (
        "right_to_erasure", "data_retention_obligation",
        "GDPR right to erasure conflicts with regulatory data retention mandates.",
    ),
    (
        "non_compete", "non_solicitation",
        "Overlapping scope may result in overbroad restrictions unenforceable in CA.",
    ),
    (
        "mandatory_arbitration", "class_action_waiver",
        "Combined clauses may violate NLRA Section 7 rights in employment contexts.",
    ),
    (
        "limitation_of_liability", "indemnification",
        "Uncapped indemnification may override liability cap; reconcile scope.",
    ),
]

# Jurisdiction-specific required clauses
_JURISDICTION_REQUIRED_CLAUSES: dict[str, list[str]] = {
    "US-CA": ["non_discrimination", "right_to_erasure"],
    "US-NY": ["governing_law", "dispute_resolution"],
    "EU": ["data_processing", "data_breach_notification", "right_to_erasure", "data_portability"],
    "UK": ["data_processing", "data_breach_notification", "anti_bribery"],
}

# Clause improvement suggestions keyed by clause type
_IMPROVEMENT_SUGGESTIONS: dict[str, list[str]] = {
    "confidentiality": [
        "Add specific definition of 'Confidential Information' with carve-outs.",
        "Include return/destruction obligations upon termination.",
        "Specify survival period after Agreement termination.",
    ],
    "limitation_of_liability": [
        "Carve out intentional misconduct and gross negligence from cap.",
        "Set aggregate cap at 12-month trailing fees for clarity.",
        "Exclude IP indemnification claims from the liability cap.",
    ],
    "data_processing": [
        "Include data sub-processor approval rights.",
        "Add cross-border transfer mechanisms (SCCs or BCRs).",
        "Specify data retention and deletion timelines.",
    ],
    "indemnification": [
        "Define indemnification trigger conditions precisely.",
        "Include notice and cooperation obligations.",
        "Require indemnitee to mitigate losses.",
    ],
}


@dataclass
class ClauseComplianceResult:
    """Result of a single clause compliance check.

    Attributes:
        clause_type: The type of clause evaluated.
        is_compliant: Whether the clause satisfies regulatory requirements.
        compliance_score: Score from 0.0 to 1.0 representing compliance level.
        applicable_regulations: Regulations that apply to this clause type.
        violations: Specific regulatory violations detected.
        suggestions: Improvement suggestions for this clause.
    """

    clause_type: str
    is_compliant: bool
    compliance_score: float
    applicable_regulations: list[str]
    violations: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


@dataclass
class ValidationReport:
    """Full validation report for a contract document.

    Attributes:
        report_id: Unique identifier for this report.
        contract_type: Type of contract validated.
        jurisdiction: Jurisdiction used for validation.
        overall_score: Aggregate compliance score 0.0-1.0.
        is_compliant: True if all required clauses pass.
        clause_results: Per-clause compliance results.
        missing_clauses: Required clauses absent from the document.
        conflicting_clause_pairs: Pairs of clauses with detected conflicts.
        critical_issues: Issues requiring immediate resolution.
        warnings: Non-blocking compliance concerns.
        recommendations: Ordered list of improvement recommendations.
    """

    report_id: str
    contract_type: str
    jurisdiction: str
    overall_score: float
    is_compliant: bool
    clause_results: list[ClauseComplianceResult]
    missing_clauses: list[str]
    conflicting_clause_pairs: list[dict[str, str]]
    critical_issues: list[str]
    warnings: list[str]
    recommendations: list[str]


class ClauseValidator:
    """Validates contract clauses for regulatory compliance.

    Checks clause completeness, regulatory mapping, conflict detection,
    and jurisdiction-specific requirements across multiple legal frameworks.
    """

    def __init__(self, strict_mode: bool = False) -> None:
        """Initialize the clause validator.

        Args:
            strict_mode: If True, treat warnings as violations in scoring.
        """
        self._strict_mode = strict_mode
        logger.info("ClauseValidator initialized", strict_mode=strict_mode)

    def score_clause(
        self,
        clause_type: str,
        clause_text: str,
        jurisdiction: str | None = None,
    ) -> ClauseComplianceResult:
        """Score a single clause for regulatory compliance.

        Evaluates the clause against its regulatory mappings and produces
        a compliance score with specific violation details.

        Args:
            clause_type: Clause type identifier (e.g., "confidentiality").
            clause_text: The raw text of the clause.
            jurisdiction: Optional jurisdiction code for specific checks.

        Returns:
            ClauseComplianceResult with detailed compliance assessment.
        """
        applicable_regs = _CLAUSE_REGULATION_MAP.get(clause_type, [])
        violations: list[str] = []
        suggestions = _IMPROVEMENT_SUGGESTIONS.get(clause_type, [])

        score = 1.0

        # Length heuristic: very short clauses are likely incomplete
        word_count = len(clause_text.split())
        if word_count < 20:
            violations.append(
                f"Clause text is unusually short ({word_count} words); likely incomplete."
            )
            score -= 0.3

        # Check for jurisdiction-specific language requirements
        if jurisdiction in _JURISDICTION_REQUIRED_CLAUSES:
            required_for_jur = _JURISDICTION_REQUIRED_CLAUSES[jurisdiction]
            if clause_type in required_for_jur:
                # Enhanced check: look for key terms in text
                key_terms = self._required_terms_for_clause(clause_type)
                missing_terms = [t for t in key_terms if t.lower() not in clause_text.lower()]
                if missing_terms:
                    violations.append(
                        f"Missing required terms for {jurisdiction}: {', '.join(missing_terms)}"
                    )
                    score -= 0.2 * len(missing_terms)

        # GDPR-specific checks for data-related clauses
        if clause_type == "data_processing" and jurisdiction and jurisdiction.startswith("EU"):
            gdpr_terms = ["sub-processor", "data subject", "personal data", "lawful basis"]
            missing = [t for t in gdpr_terms if t.lower() not in clause_text.lower()]
            for term in missing:
                violations.append(f"GDPR Art.28 requires reference to '{term}'.")
                score -= 0.15

        # Caps breach at 0
        score = max(0.0, min(1.0, score))
        is_compliant = score >= 0.7 and not any(
            "incomplete" in v.lower() for v in violations
        )

        logger.debug(
            "Clause scored",
            clause_type=clause_type,
            compliance_score=round(score, 3),
            violation_count=len(violations),
        )

        return ClauseComplianceResult(
            clause_type=clause_type,
            is_compliant=is_compliant,
            compliance_score=round(score, 3),
            applicable_regulations=applicable_regs,
            violations=violations,
            suggestions=suggestions,
        )

    def _required_terms_for_clause(self, clause_type: str) -> list[str]:
        """Return key terms that must appear in a clause of the given type.

        Args:
            clause_type: Clause type identifier.

        Returns:
            List of required term strings.
        """
        required: dict[str, list[str]] = {
            "right_to_erasure": ["erasure", "deletion", "request"],
            "data_breach_notification": ["notification", "72 hours", "supervisory authority"],
            "audit_rights": ["audit", "inspection", "records"],
            "anti_bribery": ["bribe", "corrupt", "FCPA"],
            "export_controls": ["export", "EAR", "ITAR"],
        }
        return required.get(clause_type, [])

    def detect_missing_clauses(
        self,
        present_clause_types: list[str],
        contract_type: str,
        jurisdiction: str | None = None,
    ) -> list[str]:
        """Identify required clauses missing from a contract.

        Args:
            present_clause_types: Clause types present in the document.
            contract_type: Type of contract being validated.
            jurisdiction: Optional jurisdiction for additional requirements.

        Returns:
            List of missing required clause type identifiers.
        """
        required = set(_REQUIRED_CLAUSES_BY_TYPE.get(contract_type, []))

        if jurisdiction in _JURISDICTION_REQUIRED_CLAUSES:
            required.update(_JURISDICTION_REQUIRED_CLAUSES[jurisdiction])

        present = set(present_clause_types)
        missing = list(required - present)

        logger.info(
            "Missing clause detection",
            contract_type=contract_type,
            jurisdiction=jurisdiction,
            missing_count=len(missing),
            missing=missing,
        )
        return missing

    def detect_conflicts(
        self, present_clause_types: list[str]
    ) -> list[dict[str, str]]:
        """Identify conflicting clause pairs in a contract.

        Args:
            present_clause_types: Clause types present in the document.

        Returns:
            List of conflict dicts with clause_a, clause_b, description.
        """
        present = set(present_clause_types)
        conflicts: list[dict[str, str]] = []

        for clause_a, clause_b, description in _CLAUSE_CONFLICT_PAIRS:
            if clause_a in present and clause_b in present:
                conflicts.append({
                    "clause_a": clause_a,
                    "clause_b": clause_b,
                    "conflict_description": description,
                    "severity": "high" if "NLRA" in description or "GDPR" in description else "medium",
                })

        logger.info(
            "Conflict detection complete",
            conflict_count=len(conflicts),
        )
        return conflicts

    def validate_contract(
        self,
        clauses: dict[str, str],
        contract_type: str,
        jurisdiction: str | None = None,
    ) -> ValidationReport:
        """Perform full contract validation.

        Runs clause scoring, missing clause detection, conflict detection,
        and assembles a comprehensive validation report.

        Args:
            clauses: Dict mapping clause_type -> clause_text.
            contract_type: Contract type identifier for required clause lookup.
            jurisdiction: Optional jurisdiction code for specific requirements.

        Returns:
            ValidationReport with full compliance assessment.
        """
        report_id = str(uuid.uuid4())
        logger.info(
            "Running contract validation",
            report_id=report_id,
            contract_type=contract_type,
            jurisdiction=jurisdiction,
            clause_count=len(clauses),
        )

        clause_results: list[ClauseComplianceResult] = []
        for clause_type, clause_text in clauses.items():
            result = self.score_clause(clause_type, clause_text, jurisdiction)
            clause_results.append(result)

        missing = self.detect_missing_clauses(
            list(clauses.keys()), contract_type, jurisdiction
        )
        conflicts = self.detect_conflicts(list(clauses.keys()))

        critical_issues: list[str] = []
        warnings: list[str] = []

        for missing_clause in missing:
            regs = _CLAUSE_REGULATION_MAP.get(missing_clause, [])
            if regs:
                critical_issues.append(
                    f"Missing required clause '{missing_clause}' (required by: {', '.join(regs)})"
                )
            else:
                warnings.append(f"Missing recommended clause '{missing_clause}'")

        for conflict in conflicts:
            if conflict.get("severity") == "high":
                critical_issues.append(
                    f"Clause conflict: {conflict['clause_a']} vs {conflict['clause_b']}: "
                    f"{conflict['conflict_description']}"
                )
            else:
                warnings.append(
                    f"Potential conflict: {conflict['clause_a']} vs {conflict['clause_b']}"
                )

        for result in clause_results:
            for violation in result.violations:
                if self._strict_mode:
                    critical_issues.append(f"[{result.clause_type}] {violation}")
                else:
                    warnings.append(f"[{result.clause_type}] {violation}")

        # Aggregate score: average clause scores, penalized for missing clauses
        if clause_results:
            avg_score = sum(r.compliance_score for r in clause_results) / len(clause_results)
        else:
            avg_score = 0.0
        penalty = len(missing) * 0.1 + len(conflicts) * 0.05
        overall_score = max(0.0, round(avg_score - penalty, 3))
        is_compliant = (
            not critical_issues
            and overall_score >= 0.7
            and not missing
        )

        recommendations = self._build_recommendations(clause_results, missing, conflicts)

        report = ValidationReport(
            report_id=report_id,
            contract_type=contract_type,
            jurisdiction=jurisdiction or "unspecified",
            overall_score=overall_score,
            is_compliant=is_compliant,
            clause_results=clause_results,
            missing_clauses=missing,
            conflicting_clause_pairs=conflicts,
            critical_issues=critical_issues,
            warnings=warnings,
            recommendations=recommendations,
        )

        logger.info(
            "Contract validation complete",
            report_id=report_id,
            overall_score=overall_score,
            is_compliant=is_compliant,
            critical_issue_count=len(critical_issues),
            warning_count=len(warnings),
        )
        return report

    def _build_recommendations(
        self,
        clause_results: list[ClauseComplianceResult],
        missing_clauses: list[str],
        conflicts: list[dict[str, str]],
    ) -> list[str]:
        """Build ordered list of improvement recommendations.

        Args:
            clause_results: Per-clause compliance results.
            missing_clauses: List of missing clause types.
            conflicts: Detected conflicting clause pairs.

        Returns:
            Ordered list of actionable recommendation strings.
        """
        recommendations: list[str] = []

        # Missing clauses first — highest priority
        for clause in missing_clauses:
            recommendations.append(
                f"ADD: Include a '{clause.replace('_', ' ')}' clause to satisfy "
                f"applicable regulatory requirements."
            )

        # Conflicts second
        for conflict in conflicts:
            recommendations.append(
                f"RESOLVE: Reconcile '{conflict['clause_a']}' and '{conflict['clause_b']}' "
                f"to eliminate conflict: {conflict['conflict_description']}"
            )

        # Low-scoring clauses
        for result in sorted(clause_results, key=lambda r: r.compliance_score):
            if result.compliance_score < 0.8:
                for suggestion in result.suggestions[:2]:
                    recommendations.append(
                        f"IMPROVE [{result.clause_type}]: {suggestion}"
                    )

        return recommendations[:20]  # Cap at 20 recommendations

    def get_clause_regulation_map(self) -> dict[str, list[str]]:
        """Return the full clause-to-regulation mapping.

        Returns:
            Dict of clause_type -> list of applicable regulation identifiers.
        """
        return dict(_CLAUSE_REGULATION_MAP)

    def get_required_clauses(
        self, contract_type: str, jurisdiction: str | None = None
    ) -> list[str]:
        """Return required clauses for a given contract type and jurisdiction.

        Args:
            contract_type: Contract type identifier.
            jurisdiction: Optional jurisdiction code.

        Returns:
            Combined list of required clause type identifiers.
        """
        required = set(_REQUIRED_CLAUSES_BY_TYPE.get(contract_type, []))
        if jurisdiction in _JURISDICTION_REQUIRED_CLAUSES:
            required.update(_JURISDICTION_REQUIRED_CLAUSES[jurisdiction])
        return sorted(required)

    def export_report_as_dict(self, report: ValidationReport) -> dict[str, Any]:
        """Serialize a ValidationReport to a plain dict for API responses.

        Args:
            report: The ValidationReport to serialize.

        Returns:
            Plain dict representation suitable for JSON serialization.
        """
        return {
            "report_id": report.report_id,
            "contract_type": report.contract_type,
            "jurisdiction": report.jurisdiction,
            "overall_score": report.overall_score,
            "is_compliant": report.is_compliant,
            "clause_results": [
                {
                    "clause_type": r.clause_type,
                    "is_compliant": r.is_compliant,
                    "compliance_score": r.compliance_score,
                    "applicable_regulations": r.applicable_regulations,
                    "violations": r.violations,
                    "suggestions": r.suggestions,
                }
                for r in report.clause_results
            ],
            "missing_clauses": report.missing_clauses,
            "conflicting_clause_pairs": report.conflicting_clause_pairs,
            "critical_issues": report.critical_issues,
            "warnings": report.warnings,
            "recommendations": report.recommendations,
        }


__all__ = ["ClauseValidator", "ClauseComplianceResult", "ValidationReport"]
