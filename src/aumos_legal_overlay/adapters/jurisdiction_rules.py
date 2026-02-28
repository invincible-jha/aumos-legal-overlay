"""Multi-jurisdictional privilege rule engine.

GAP-319: Multi-Jurisdictional Privilege Rules.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


@dataclass
class JurisdictionRule:
    """A privilege rule specific to a jurisdiction.

    Covers US federal, US state, and international jurisdictions.
    jurisdiction_code uses ISO 3166-2 for US states (e.g., "US-CA", "US-NY")
    and ISO 3166-1 alpha-2 for countries (e.g., "UK", "DE", "AU").
    """

    jurisdiction_code: str          # e.g., "US-CA", "UK", "DE", "US-FEDERAL"
    rule_type: str                  # attorney_client | work_product | common_interest | mediation
    description: str
    effective_date: date
    supersedes_rule_id: str | None = None
    is_active: bool = True
    citation: str = ""              # Statutory or case law citation
    notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


# Bundled default rules for major jurisdictions
# Source: Restatement (Third) of The Law Governing Lawyers and jurisdiction-specific statutes
BUILT_IN_RULES: list[dict[str, Any]] = [
    # US Federal
    {
        "jurisdiction_code": "US-FEDERAL",
        "rule_type": "attorney_client",
        "description": (
            "Attorney-client privilege protects confidential communications between "
            "attorney and client made for the purpose of obtaining or providing legal advice. "
            "FRE 501; Upjohn Co. v. United States, 449 U.S. 383 (1981)."
        ),
        "effective_date": date(1975, 1, 2),
        "citation": "FRE 501; 28 U.S.C. § 1652",
        "notes": "Federal common law privilege. Corporate communications: Upjohn test applies.",
    },
    {
        "jurisdiction_code": "US-FEDERAL",
        "rule_type": "work_product",
        "description": (
            "Work product doctrine protects materials prepared in anticipation of litigation "
            "or for trial by or for a party or its representative. "
            "Hickman v. Taylor, 329 U.S. 495 (1947); FRCP 26(b)(3)."
        ),
        "effective_date": date(1947, 1, 14),
        "citation": "FRCP 26(b)(3); Hickman v. Taylor, 329 U.S. 495 (1947)",
        "notes": "Qualified protection. Mental impressions/opinions have absolute protection.",
    },
    {
        "jurisdiction_code": "US-FEDERAL",
        "rule_type": "common_interest",
        "description": (
            "Common interest doctrine extends privilege to communications among parties "
            "with a common legal interest, typically co-defendants or co-plaintiffs "
            "sharing litigation strategy. No waiver when shared among aligned parties."
        ),
        "effective_date": date(1975, 1, 2),
        "citation": "United States v. Schwimmer, 892 F.2d 237 (2d Cir. 1989)",
        "notes": "Must share identical, not merely similar, legal interests.",
    },
    # California
    {
        "jurisdiction_code": "US-CA",
        "rule_type": "attorney_client",
        "description": (
            "California Evidence Code §§ 950-962 provides the attorney-client privilege. "
            "California's privilege is broader than federal common law. "
            "Applies to all confidential communications to counsel for purpose of legal representation."
        ),
        "effective_date": date(1967, 1, 1),
        "citation": "Cal. Evid. Code §§ 950-962",
        "notes": "Holder is the client. Attorney may claim on client's behalf. "
                 "Crime-fraud exception applies (§ 956).",
    },
    {
        "jurisdiction_code": "US-CA",
        "rule_type": "mediation",
        "description": (
            "California Evidence Code §§ 1115-1128 provides the mediation privilege. "
            "California has the strongest mediation confidentiality in the US. "
            "Covers all communications, writings, and conduct during mediation."
        ),
        "effective_date": date(1998, 1, 1),
        "citation": "Cal. Evid. Code §§ 1115-1128",
        "notes": "Absolute protection. No exception for fraud. Cassel v. Superior Court (2011).",
    },
    # New York
    {
        "jurisdiction_code": "US-NY",
        "rule_type": "attorney_client",
        "description": (
            "New York CPLR § 4503 and common law attorney-client privilege. "
            "Protects confidential communications between attorney and client. "
            "Corporate exception: Commodity Exchange Act analysis may apply for in-house counsel."
        ),
        "effective_date": date(1963, 9, 1),
        "citation": "NY CPLR § 4503; NY Evid. Law § 911",
        "notes": "In-house counsel communications protected only when providing legal (not business) advice.",
    },
    # United Kingdom
    {
        "jurisdiction_code": "UK",
        "rule_type": "attorney_client",
        "description": (
            "Legal Professional Privilege (LPP) in England and Wales covers legal advice "
            "privilege and litigation privilege. Legal advice privilege: communications "
            "between solicitor and client for purpose of giving/receiving legal advice. "
            "Three Rivers (No. 6) [2004] UKHL 48."
        ),
        "effective_date": date(2004, 10, 28),
        "citation": "Three Rivers DC v. Bank of England (No. 6) [2004] UKHL 48",
        "notes": "Narrower than US corporate privilege — only communications from "
                 "designated 'client' employees to external counsel protected. "
                 "In-house counsel LPP limited: R (ENRC) v Director of the SFO [2018].",
    },
    {
        "jurisdiction_code": "UK",
        "rule_type": "work_product",
        "description": (
            "Litigation privilege in England and Wales protects communications "
            "between client, lawyers, and third parties when dominant purpose is "
            "preparation for litigation that is reasonably anticipated."
        ),
        "effective_date": date(2004, 10, 28),
        "citation": "Dominant purpose test: Waugh v. British Railways Board [1980] AC 521",
        "notes": "Dominant (not merely one of the) purposes must be litigation preparation.",
    },
    # Germany
    {
        "jurisdiction_code": "DE",
        "rule_type": "attorney_client",
        "description": (
            "German attorney secrecy (Anwaltliche Verschwiegenheitspflicht) under "
            "§ 203 StGB (criminal law) and § 43a BRAO (professional duty). "
            "In-house counsel (Syndikusrechtsanwälte) protected under § 46 BRAO since 2016."
        ),
        "effective_date": date(2016, 1, 1),
        "citation": "§ 43a BRAO; § 203 StGB; § 46 BRAO (in-house counsel, 2016 amendment)",
        "notes": "EU competition law exception: in-house counsel communications not protected "
                 "in EU Commission investigations (AM&S; Akzo Nobel [2010]).",
    },
    # European Union
    {
        "jurisdiction_code": "EU",
        "rule_type": "attorney_client",
        "description": (
            "EU privilege under Article 47 of the EU Charter covers independent "
            "external counsel only. Communications with in-house counsel not privileged "
            "in EU Commission competition investigations. "
            "Akzo Nobel Chemicals v. Commission C-550/07 P (2010)."
        ),
        "effective_date": date(2010, 9, 14),
        "citation": "Akzo Nobel Chemicals Ltd v. Commission, C-550/07 P (ECJ 2010)",
        "notes": "External independent counsel only. In-house counsel not covered "
                 "regardless of bar admission or seniority.",
    },
    # Australia
    {
        "jurisdiction_code": "AU",
        "rule_type": "attorney_client",
        "description": (
            "Legal professional privilege (LPP) in Australia under common law and "
            "Evidence Act 1995 (Cth) §§ 117-131B. Covers confidential communications "
            "made for dominant purpose of legal advice or litigation."
        ),
        "effective_date": date(1995, 4, 18),
        "citation": "Evidence Act 1995 (Cth) §§ 117-131B; Esso Australia Resources v. Commissioner [1999] HCA 67",
        "notes": "Dominant purpose test. Crime-fraud exception applies. "
                 "State and territory Evidence Acts may vary.",
    },
]


class JurisdictionRuleEngine:
    """Configurable multi-jurisdictional privilege rule engine.

    Ships with built-in rules for major jurisdictions (US Federal, CA, NY, UK, DE, EU, AU).
    Supports runtime addition of custom rules for specialized jurisdictions.
    Rules are versioned — superseded rules are preserved for historical analysis.
    """

    def __init__(self) -> None:
        self._rules: list[JurisdictionRule] = []
        self._load_built_in_rules()

    def _load_built_in_rules(self) -> None:
        """Load built-in jurisdiction rules from the bundled rule set."""
        for rule_data in BUILT_IN_RULES:
            self._rules.append(JurisdictionRule(**rule_data))
        logger.info("jurisdiction_rules_loaded", count=len(self._rules))

    def get_rules(
        self,
        jurisdiction_code: str,
        rule_type: str | None = None,
        as_of_date: date | None = None,
    ) -> list[JurisdictionRule]:
        """Get privilege rules for a jurisdiction.

        Args:
            jurisdiction_code: Jurisdiction identifier (e.g., "US-CA", "UK", "DE").
                               Searches both exact match and parent jurisdiction
                               (e.g., "US-CA" query also returns "US-FEDERAL" rules).
            rule_type: Optional filter by privilege type (attorney_client, work_product, etc.).
            as_of_date: Return rules effective as of this date (default: today).

        Returns:
            List of JurisdictionRule records matching the query, ordered by specificity
            (jurisdiction-specific rules before federal/country-level rules).
        """
        effective_date = as_of_date or datetime.now(timezone.utc).date()

        # Build jurisdiction search set: exact match + parent jurisdictions
        search_codes = {jurisdiction_code}
        if jurisdiction_code.startswith("US-") and jurisdiction_code != "US-FEDERAL":
            search_codes.add("US-FEDERAL")
        if jurisdiction_code in ("UK", "DE", "FR", "IT", "ES", "NL", "BE", "SE", "PL"):
            search_codes.add("EU")

        matching = [
            rule for rule in self._rules
            if rule.jurisdiction_code in search_codes
            and rule.is_active
            and rule.effective_date <= effective_date
            and (rule_type is None or rule.rule_type == rule_type)
        ]

        # Sort: jurisdiction-specific rules first, then broader (federal/EU)
        matching.sort(
            key=lambda r: (0 if r.jurisdiction_code == jurisdiction_code else 1, r.effective_date),
            reverse=False,
        )
        return matching

    def add_custom_rule(self, rule: JurisdictionRule) -> None:
        """Add a custom jurisdiction rule.

        Args:
            rule: JurisdictionRule to add. Will supersede existing rules
                  if rule.supersedes_rule_id is set.
        """
        if rule.supersedes_rule_id:
            for existing in self._rules:
                if hasattr(existing, "rule_id") and getattr(existing, "rule_id", None) == rule.supersedes_rule_id:
                    existing.is_active = False
        self._rules.append(rule)
        logger.info(
            "jurisdiction_rule_added",
            jurisdiction_code=rule.jurisdiction_code,
            rule_type=rule.rule_type,
        )

    def assess_privilege_risk(
        self,
        jurisdiction_code: str,
        communication_type: str,
        is_in_house_counsel: bool = False,
        is_litigation_anticipated: bool = False,
    ) -> dict[str, Any]:
        """Assess privilege risk for a communication in a given jurisdiction.

        Args:
            jurisdiction_code: Jurisdiction where privilege is assessed.
            communication_type: Type of communication (email, memo, meeting_notes, etc.).
            is_in_house_counsel: Whether the communication involves in-house counsel only.
            is_litigation_anticipated: Whether litigation is anticipated at time of communication.

        Returns:
            Risk assessment dict with privilege_likely, risk_level, applicable_rules, and notes.
        """
        applicable_rules = self.get_rules(jurisdiction_code)
        risk_notes: list[str] = []

        # In-house counsel risk assessment
        privilege_likely = True
        if is_in_house_counsel:
            if jurisdiction_code in ("EU", "DE") or jurisdiction_code.startswith("EU-"):
                privilege_likely = False
                risk_notes.append(
                    "EU/German in-house counsel communications are NOT protected "
                    "in competition investigations (Akzo Nobel 2010)."
                )
            elif jurisdiction_code == "UK":
                risk_notes.append(
                    "UK in-house counsel LPP is limited to designated 'client' employees "
                    "only (Three Rivers No. 6). Verify communication falls within scope."
                )

        # Work product risk without litigation
        if communication_type in ("strategy_memo", "analysis_memo") and not is_litigation_anticipated:
            risk_notes.append(
                "Work product doctrine requires litigation to be anticipated at time of creation. "
                "General business strategy memos may not qualify."
            )

        risk_level = "low" if privilege_likely and not risk_notes else (
            "high" if not privilege_likely else "medium"
        )

        return {
            "jurisdiction_code": jurisdiction_code,
            "communication_type": communication_type,
            "privilege_likely": privilege_likely,
            "risk_level": risk_level,
            "applicable_rules": [
                {
                    "jurisdiction_code": r.jurisdiction_code,
                    "rule_type": r.rule_type,
                    "citation": r.citation,
                    "description": r.description[:200],
                }
                for r in applicable_rules
            ],
            "risk_notes": risk_notes,
        }
