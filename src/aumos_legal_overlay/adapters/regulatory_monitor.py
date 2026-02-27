"""Regulatory monitor adapter for aumos-legal-overlay.

Monitors emerging AI regulations across jurisdictions, scores relevance,
tracks regulatory changes, and dispatches alerts to stakeholders.
"""

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)


# Simulated regulatory feed database (represents parsed RSS/API sources)
_REGULATORY_FEEDS: dict[str, dict[str, Any]] = {
    "EU_AI_ACT": {
        "jurisdiction": "EU",
        "title": "EU Artificial Intelligence Act",
        "source_url": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
        "effective_date": "2024-08-01",
        "full_implementation_date": "2026-08-01",
        "status": "enacted",
        "impact_level": "critical",
        "affected_sectors": ["all"],
        "key_requirements": [
            "High-risk AI system conformity assessment",
            "Technical documentation requirements",
            "Human oversight for high-risk systems",
            "Prohibited AI practices ban",
            "GPAI model transparency obligations",
        ],
        "penalties": "Up to €35M or 7% of global turnover",
        "tags": ["ai", "risk_management", "transparency", "conformity"],
    },
    "NIST_AI_RMF": {
        "jurisdiction": "US",
        "title": "NIST AI Risk Management Framework 1.0",
        "source_url": "https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf",
        "effective_date": "2023-01-26",
        "full_implementation_date": "2023-01-26",
        "status": "enacted",
        "impact_level": "high",
        "affected_sectors": ["federal_contractors", "financial", "healthcare"],
        "key_requirements": [
            "AI risk management across GOVERN, MAP, MEASURE, MANAGE",
            "AI system documentation and accountability",
            "Bias and fairness assessment",
        ],
        "penalties": "No mandatory penalties; FedRAMP implications for federal",
        "tags": ["ai", "risk_management", "federal"],
    },
    "CCPA_CPRA": {
        "jurisdiction": "US-CA",
        "title": "California Consumer Privacy Act / California Privacy Rights Act",
        "source_url": "https://oag.ca.gov/privacy/ccpa",
        "effective_date": "2020-01-01",
        "full_implementation_date": "2023-01-01",
        "status": "enacted",
        "impact_level": "high",
        "affected_sectors": ["all_california"],
        "key_requirements": [
            "Opt-out from automated decision-making",
            "Access and deletion rights",
            "Data minimization requirements",
            "Privacy by design",
        ],
        "penalties": "Up to $7,500 per intentional violation",
        "tags": ["privacy", "automated_decisions", "data_rights"],
    },
    "EU_AI_LIABILITY": {
        "jurisdiction": "EU",
        "title": "EU AI Liability Directive",
        "source_url": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:52022PC0496",
        "effective_date": "2026-01-01",
        "full_implementation_date": "2027-01-01",
        "status": "proposed",
        "impact_level": "critical",
        "affected_sectors": ["all"],
        "key_requirements": [
            "Rebuttable presumption of causality for high-risk AI",
            "Access to evidence disclosure obligations",
            "Burden of proof reversal for high-risk systems",
        ],
        "penalties": "Civil liability — compensatory damages",
        "tags": ["liability", "ai", "high_risk"],
    },
    "UK_AI_SAFETY": {
        "jurisdiction": "UK",
        "title": "UK AI Safety Institute Guidelines",
        "source_url": "https://www.gov.uk/government/organisations/ai-safety-institute",
        "effective_date": "2024-02-01",
        "full_implementation_date": "2024-06-01",
        "status": "enacted",
        "impact_level": "medium",
        "affected_sectors": ["frontier_models", "critical_national_infrastructure"],
        "key_requirements": [
            "Pre-deployment safety evaluations",
            "Red-teaming requirements for frontier models",
            "Incident reporting to DSIT",
        ],
        "penalties": "Non-binding guidelines currently",
        "tags": ["safety", "frontier_models", "evaluation"],
    },
    "HIPAA_AI": {
        "jurisdiction": "US",
        "title": "HIPAA AI Guidance — OCR Bulletin on AI in Healthcare",
        "source_url": "https://www.hhs.gov/ocr/",
        "effective_date": "2024-03-15",
        "full_implementation_date": "2024-03-15",
        "status": "enacted",
        "impact_level": "high",
        "affected_sectors": ["healthcare"],
        "key_requirements": [
            "HIPAA compliance for AI tools processing PHI",
            "BAA requirements for AI vendors",
            "Non-discrimination requirements for AI diagnosis",
        ],
        "penalties": "Up to $1.9M per violation category per year",
        "tags": ["healthcare", "phi", "privacy", "discrimination"],
    },
    "EXECUTIVE_ORDER_AI": {
        "jurisdiction": "US",
        "title": "Executive Order on Safe, Secure, and Trustworthy AI",
        "source_url": "https://www.whitehouse.gov/briefing-room/presidential-actions/2023/10/30/executive-order-on-the-safe-secure-and-trustworthy-development-and-use-of-artificial-intelligence/",
        "effective_date": "2023-10-30",
        "full_implementation_date": "2024-07-01",
        "status": "enacted",
        "impact_level": "high",
        "affected_sectors": ["federal_agencies", "ai_developers", "critical_infrastructure"],
        "key_requirements": [
            "Safety and security standards for foundation models",
            "Red-team testing for dual-use models",
            "Reporting requirements for advanced AI",
            "Watermarking standards for AI-generated content",
        ],
        "penalties": "Regulatory enforcement by sector agencies",
        "tags": ["safety", "security", "federal", "watermarking", "foundation_models"],
    },
}

# Stakeholder alert routing by impact level and sector
_STAKEHOLDER_ROUTING: dict[str, list[str]] = {
    "critical": ["general_counsel", "chief_compliance_officer", "ceo", "board_audit_committee"],
    "high": ["general_counsel", "chief_compliance_officer", "dpo"],
    "medium": ["legal_team", "compliance_team"],
    "low": ["compliance_team"],
}

# Sector keyword matching for relevance scoring
_SECTOR_KEYWORDS: dict[str, list[str]] = {
    "healthcare": ["hipaa", "phi", "medical", "clinical", "diagnostic", "patient"],
    "financial": ["cfpb", "finra", "credit", "lending", "banking", "investment"],
    "critical_infrastructure": ["scada", "ot", "power", "grid", "water", "transport"],
    "ai_development": ["training", "model", "llm", "foundation", "frontier", "algorithm"],
    "data_privacy": ["privacy", "gdpr", "ccpa", "personal data", "data subject"],
}


@dataclass
class RegulatoryAlert:
    """A regulatory alert for a specific regulation.

    Attributes:
        alert_id: Unique identifier for this alert.
        regulation_id: Key of the regulation that triggered the alert.
        title: Regulation title.
        jurisdiction: Jurisdiction of the regulation.
        impact_level: Impact level (critical, high, medium, low).
        relevance_score: Relevance score 0.0-1.0 for the tenant's sector.
        effective_date: When the regulation takes effect.
        key_requirements: Summary of key requirements.
        action_items: Specific actions required for compliance.
        stakeholders_to_notify: List of stakeholder roles to notify.
        alert_generated_at: Timestamp of alert generation.
    """

    alert_id: str
    regulation_id: str
    title: str
    jurisdiction: str
    impact_level: str
    relevance_score: float
    effective_date: str
    key_requirements: list[str]
    action_items: list[str]
    stakeholders_to_notify: list[str]
    alert_generated_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


@dataclass
class RegulatoryLandscapeReport:
    """A comprehensive report on the regulatory landscape.

    Attributes:
        report_id: Unique report identifier.
        generated_at: Report generation timestamp.
        jurisdictions_covered: Jurisdictions included in the report.
        sectors_analyzed: Sectors analyzed for relevance.
        total_regulations: Total regulations in the feed.
        critical_count: Number of critical-impact regulations.
        high_count: Number of high-impact regulations.
        upcoming_deadlines: Regulations with upcoming effective dates.
        regulatory_trends: Identified regulatory trend patterns.
        regulation_summaries: Per-regulation summary dicts.
    """

    report_id: str
    generated_at: datetime
    jurisdictions_covered: list[str]
    sectors_analyzed: list[str]
    total_regulations: int
    critical_count: int
    high_count: int
    upcoming_deadlines: list[dict[str, Any]]
    regulatory_trends: list[str]
    regulation_summaries: list[dict[str, Any]]


class RegulatoryMonitor:
    """Monitors emerging AI regulations and dispatches stakeholder alerts.

    Parses simulated regulatory feeds, scores relevance to tenant sectors,
    identifies upcoming deadlines, dispatches alerts, and generates
    comprehensive regulatory landscape reports.
    """

    def __init__(
        self,
        tenant_sectors: list[str] | None = None,
        monitored_jurisdictions: list[str] | None = None,
    ) -> None:
        """Initialize the regulatory monitor.

        Args:
            tenant_sectors: Sectors the tenant operates in for relevance scoring.
            monitored_jurisdictions: Jurisdictions to monitor; all if None.
        """
        self._tenant_sectors = tenant_sectors or ["ai_development", "data_privacy"]
        self._monitored_jurisdictions = monitored_jurisdictions
        self._dispatched_alerts: list[RegulatoryAlert] = []
        logger.info(
            "RegulatoryMonitor initialized",
            sectors=self._tenant_sectors,
            jurisdictions=monitored_jurisdictions,
        )

    def _filter_by_jurisdiction(
        self, regulations: dict[str, dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        """Filter regulations to monitored jurisdictions.

        Args:
            regulations: Full regulations dict.

        Returns:
            Filtered regulations dict.
        """
        if not self._monitored_jurisdictions:
            return regulations
        return {
            reg_id: reg
            for reg_id, reg in regulations.items()
            if reg["jurisdiction"] in self._monitored_jurisdictions
        }

    def score_relevance(
        self, regulation: dict[str, Any], tenant_sectors: list[str]
    ) -> float:
        """Score regulation relevance to the tenant's sectors.

        Args:
            regulation: Regulation data dict.
            tenant_sectors: Tenant's operating sectors.

        Returns:
            Relevance score from 0.0 to 1.0.
        """
        affected = regulation.get("affected_sectors", [])
        tags = regulation.get("tags", [])
        impact = regulation.get("impact_level", "low")

        score = 0.0

        # Impact level base score
        impact_weights = {"critical": 0.6, "high": 0.4, "medium": 0.2, "low": 0.1}
        score += impact_weights.get(impact, 0.1)

        # Sector match bonus
        if "all" in affected:
            score += 0.3
        else:
            for sector in tenant_sectors:
                if sector in affected:
                    score += 0.2
                    break

        # Keyword match in tags
        for sector in tenant_sectors:
            sector_keywords = _SECTOR_KEYWORDS.get(sector, [])
            matched = sum(1 for kw in sector_keywords if any(kw in tag for tag in tags))
            score += matched * 0.05

        return round(min(1.0, score), 3)

    def _generate_action_items(
        self, regulation: dict[str, Any], relevance_score: float
    ) -> list[str]:
        """Generate specific action items for a regulation.

        Args:
            regulation: Regulation data dict.
            relevance_score: Computed relevance score.

        Returns:
            List of actionable compliance steps.
        """
        actions: list[str] = []
        impact = regulation.get("impact_level", "low")

        if impact in ("critical", "high"):
            actions.append(
                f"Assign compliance owner for '{regulation['title']}' by end of quarter."
            )
            actions.append(
                f"Conduct gap analysis against: {', '.join(regulation.get('key_requirements', [])[:2])}."
            )
        actions.append(
            f"Review full text at: {regulation.get('source_url', 'regulatory source')}."
        )
        if regulation.get("effective_date"):
            actions.append(
                f"Calendar compliance deadline: {regulation['effective_date']}."
            )
        if regulation.get("penalties"):
            actions.append(
                f"Assess penalty exposure: {regulation['penalties']}."
            )
        return actions

    def parse_regulatory_feeds(
        self,
        jurisdictions: list[str] | None = None,
        impact_threshold: str = "medium",
    ) -> list[dict[str, Any]]:
        """Parse and return regulatory feed entries.

        Args:
            jurisdictions: Jurisdictions to include; uses instance default if None.
            impact_threshold: Minimum impact level to include.

        Returns:
            List of regulation data dicts with relevance scores.
        """
        impact_order = ["low", "medium", "high", "critical"]
        threshold_index = impact_order.index(impact_threshold)

        regs = self._filter_by_jurisdiction(_REGULATORY_FEEDS)
        if jurisdictions:
            regs = {k: v for k, v in regs.items() if v["jurisdiction"] in jurisdictions}

        result: list[dict[str, Any]] = []
        for reg_id, reg in regs.items():
            impact = reg.get("impact_level", "low")
            if impact_order.index(impact) >= threshold_index:
                relevance = self.score_relevance(reg, self._tenant_sectors)
                result.append({
                    "regulation_id": reg_id,
                    "relevance_score": relevance,
                    **reg,
                })

        result.sort(key=lambda r: r["relevance_score"], reverse=True)
        logger.info(
            "Regulatory feeds parsed",
            regulation_count=len(result),
            impact_threshold=impact_threshold,
        )
        return result

    def assess_regulatory_impact(
        self,
        regulation_id: str,
        business_activities: list[str],
    ) -> dict[str, Any]:
        """Assess the impact of a specific regulation on business activities.

        Args:
            regulation_id: Regulation identifier from the feed.
            business_activities: List of relevant business activity descriptions.

        Returns:
            Impact assessment dict with affected activities and compliance gaps.
        """
        if regulation_id not in _REGULATORY_FEEDS:
            return {
                "regulation_id": regulation_id,
                "status": "not_found",
                "message": f"Regulation '{regulation_id}' not in feed.",
            }

        regulation = _REGULATORY_FEEDS[regulation_id]
        requirements = regulation.get("key_requirements", [])
        tags = regulation.get("tags", [])

        # Heuristic: check business activity text against regulation tags
        affected_activities: list[str] = []
        for activity in business_activities:
            activity_lower = activity.lower()
            for tag in tags:
                if tag.lower() in activity_lower:
                    affected_activities.append(activity)
                    break

        compliance_gaps = [
            f"Requirement not yet addressed: {req}"
            for req in requirements[:4]
        ]

        return {
            "regulation_id": regulation_id,
            "regulation_title": regulation["title"],
            "jurisdiction": regulation["jurisdiction"],
            "impact_level": regulation["impact_level"],
            "affected_activities": affected_activities,
            "compliance_gaps": compliance_gaps,
            "effective_date": regulation.get("effective_date"),
            "penalties": regulation.get("penalties"),
            "recommended_actions": self._generate_action_items(regulation, 0.8),
        }

    def generate_alert(
        self, regulation_id: str, tenant_sectors: list[str] | None = None
    ) -> RegulatoryAlert | None:
        """Generate a stakeholder alert for a regulation.

        Args:
            regulation_id: Regulation identifier.
            tenant_sectors: Override tenant sectors for relevance scoring.

        Returns:
            RegulatoryAlert if regulation is found and relevant, else None.
        """
        if regulation_id not in _REGULATORY_FEEDS:
            logger.warning("Regulation not found for alert", regulation_id=regulation_id)
            return None

        reg = _REGULATORY_FEEDS[regulation_id]
        sectors = tenant_sectors or self._tenant_sectors
        relevance = self.score_relevance(reg, sectors)

        impact = reg.get("impact_level", "low")
        stakeholders = _STAKEHOLDER_ROUTING.get(impact, ["compliance_team"])
        actions = self._generate_action_items(reg, relevance)

        alert = RegulatoryAlert(
            alert_id=str(uuid.uuid4()),
            regulation_id=regulation_id,
            title=reg["title"],
            jurisdiction=reg["jurisdiction"],
            impact_level=impact,
            relevance_score=relevance,
            effective_date=reg.get("effective_date", "TBD"),
            key_requirements=reg.get("key_requirements", []),
            action_items=actions,
            stakeholders_to_notify=stakeholders,
        )
        self._dispatched_alerts.append(alert)

        logger.info(
            "Regulatory alert generated",
            alert_id=alert.alert_id,
            regulation_id=regulation_id,
            impact_level=impact,
            relevance_score=relevance,
            stakeholder_count=len(stakeholders),
        )
        return alert

    def dispatch_alerts(
        self,
        impact_threshold: str = "high",
        jurisdictions: list[str] | None = None,
    ) -> list[RegulatoryAlert]:
        """Dispatch alerts for all regulations above the impact threshold.

        Args:
            impact_threshold: Minimum impact level to alert on.
            jurisdictions: Jurisdictions to include; all if None.

        Returns:
            List of generated RegulatoryAlerts.
        """
        feeds = self.parse_regulatory_feeds(
            jurisdictions=jurisdictions,
            impact_threshold=impact_threshold,
        )
        alerts: list[RegulatoryAlert] = []
        for reg in feeds:
            alert = self.generate_alert(reg["regulation_id"])
            if alert and alert.relevance_score >= 0.3:
                alerts.append(alert)

        logger.info(
            "Alert dispatch complete",
            alert_count=len(alerts),
            impact_threshold=impact_threshold,
        )
        return alerts

    def track_regulatory_changes(
        self, since_date: datetime | None = None
    ) -> list[dict[str, Any]]:
        """Track regulations that have changed or taken effect recently.

        Args:
            since_date: Only include regulations effective after this date.

        Returns:
            List of recently effective or changed regulation summaries.
        """
        since = since_date or datetime.now(tz=timezone.utc) - timedelta(days=180)
        recently_effective: list[dict[str, Any]] = []

        for reg_id, reg in _REGULATORY_FEEDS.items():
            eff_date_str = reg.get("effective_date")
            if not eff_date_str:
                continue
            try:
                eff_date = datetime.strptime(eff_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if eff_date >= since:
                    recently_effective.append({
                        "regulation_id": reg_id,
                        "title": reg["title"],
                        "jurisdiction": reg["jurisdiction"],
                        "effective_date": eff_date_str,
                        "status": reg["status"],
                        "impact_level": reg["impact_level"],
                        "days_since_effective": (datetime.now(tz=timezone.utc) - eff_date).days,
                    })
            except ValueError:
                continue

        recently_effective.sort(key=lambda r: r["effective_date"], reverse=True)
        logger.info(
            "Regulatory change tracking complete",
            changes_found=len(recently_effective),
        )
        return recently_effective

    def generate_landscape_report(
        self,
        jurisdictions: list[str] | None = None,
    ) -> RegulatoryLandscapeReport:
        """Generate a comprehensive regulatory landscape report.

        Args:
            jurisdictions: Jurisdictions to include; all if None.

        Returns:
            RegulatoryLandscapeReport with full landscape analysis.
        """
        report_id = str(uuid.uuid4())
        regs = self._filter_by_jurisdiction(_REGULATORY_FEEDS)
        if jurisdictions:
            regs = {k: v for k, v in regs.items() if v["jurisdiction"] in jurisdictions}

        unique_jurisdictions = list({r["jurisdiction"] for r in regs.values()})
        now = datetime.now(tz=timezone.utc)

        critical_count = sum(1 for r in regs.values() if r.get("impact_level") == "critical")
        high_count = sum(1 for r in regs.values() if r.get("impact_level") == "high")

        # Upcoming deadlines within 12 months
        upcoming_deadlines: list[dict[str, Any]] = []
        for reg_id, reg in regs.items():
            for date_field in ("effective_date", "full_implementation_date"):
                date_str = reg.get(date_field)
                if not date_str:
                    continue
                try:
                    eff_dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    delta_days = (eff_dt - now).days
                    if 0 < delta_days <= 365:
                        upcoming_deadlines.append({
                            "regulation_id": reg_id,
                            "title": reg["title"],
                            "deadline_type": date_field,
                            "date": date_str,
                            "days_remaining": delta_days,
                            "impact_level": reg.get("impact_level"),
                        })
                except ValueError:
                    continue

        upcoming_deadlines.sort(key=lambda d: d["days_remaining"])

        # Regulatory trend identification
        trends: list[str] = []
        if critical_count >= 2:
            trends.append(f"{critical_count} critical-impact AI regulations require immediate compliance planning.")
        if any("automated_decisions" in r.get("tags", []) for r in regs.values()):
            trends.append("Automated decision-making is a primary regulatory focus across multiple jurisdictions.")
        if any("liability" in r.get("tags", []) for r in regs.values()):
            trends.append("AI-specific liability frameworks are emerging, shifting burden of proof to developers.")
        if len(unique_jurisdictions) >= 3:
            trends.append("Regulatory fragmentation across jurisdictions requires multi-framework compliance strategy.")

        summaries = [
            {
                "regulation_id": reg_id,
                "title": reg["title"],
                "jurisdiction": reg["jurisdiction"],
                "status": reg["status"],
                "impact_level": reg["impact_level"],
                "effective_date": reg.get("effective_date"),
                "relevance_score": self.score_relevance(reg, self._tenant_sectors),
                "penalties": reg.get("penalties"),
            }
            for reg_id, reg in regs.items()
        ]
        summaries.sort(key=lambda s: s["relevance_score"], reverse=True)

        report = RegulatoryLandscapeReport(
            report_id=report_id,
            generated_at=now,
            jurisdictions_covered=unique_jurisdictions,
            sectors_analyzed=self._tenant_sectors,
            total_regulations=len(regs),
            critical_count=critical_count,
            high_count=high_count,
            upcoming_deadlines=upcoming_deadlines,
            regulatory_trends=trends,
            regulation_summaries=summaries,
        )

        logger.info(
            "Regulatory landscape report generated",
            report_id=report_id,
            total_regulations=len(regs),
            critical_count=critical_count,
            upcoming_deadline_count=len(upcoming_deadlines),
        )
        return report

    def get_dispatched_alerts(self) -> list[RegulatoryAlert]:
        """Return all alerts dispatched in this monitor session.

        Returns:
            List of RegulatoryAlert instances dispatched so far.
        """
        return list(self._dispatched_alerts)


__all__ = ["RegulatoryMonitor", "RegulatoryAlert", "RegulatoryLandscapeReport"]
