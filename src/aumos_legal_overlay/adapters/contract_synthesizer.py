"""Contract synthesizer adapter for aumos-legal-overlay.

Generates synthetic legal contracts with realistic clauses, parties,
jurisdictions, and document structures for legal AI training and testing.
"""

import random
import uuid
from datetime import date, timedelta
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# Contract template library: type -> (title, required_sections)
_CONTRACT_TEMPLATES: dict[str, dict[str, Any]] = {
    "NDA": {
        "title": "Non-Disclosure Agreement",
        "required_sections": [
            "definitions", "obligations_of_receiving_party", "exclusions",
            "term", "return_of_information", "injunctive_relief",
            "governing_law", "entire_agreement",
        ],
        "optional_sections": ["mutual_obligations", "liquidated_damages", "arbitration"],
    },
    "MSA": {
        "title": "Master Services Agreement",
        "required_sections": [
            "services_scope", "payment_terms", "intellectual_property",
            "confidentiality", "warranties", "limitation_of_liability",
            "indemnification", "term_and_termination", "governing_law",
        ],
        "optional_sections": ["sla_attachment", "data_processing", "insurance"],
    },
    "SLA": {
        "title": "Service Level Agreement",
        "required_sections": [
            "service_description", "availability_targets", "performance_metrics",
            "incident_response", "credits_and_remedies", "measurement_methodology",
            "reporting", "exclusions",
        ],
        "optional_sections": ["escalation_matrix", "capacity_planning"],
    },
    "EMPLOYMENT": {
        "title": "Employment Agreement",
        "required_sections": [
            "position_and_duties", "compensation", "benefits", "at_will_employment",
            "confidentiality", "non_solicitation", "intellectual_property_assignment",
            "arbitration", "governing_law",
        ],
        "optional_sections": ["non_compete", "severance", "equity_compensation"],
    },
    "VENDOR": {
        "title": "Vendor Agreement",
        "required_sections": [
            "purchase_order_terms", "delivery_terms", "warranty",
            "payment_terms", "acceptance", "risk_of_loss",
            "indemnification", "limitation_of_liability",
        ],
        "optional_sections": ["audit_rights", "insurance_requirements", "data_security"],
    },
}

# Jurisdiction-specific legal language adaptations
_JURISDICTION_ADAPTATIONS: dict[str, dict[str, str]] = {
    "US-CA": {
        "governing_law": "laws of the State of California",
        "courts": "courts of Santa Clara County, California",
        "non_compete_note": "Non-compete provisions are unenforceable under California Business and Professions Code Section 16600.",
        "arbitration_provider": "JAMS",
    },
    "US-NY": {
        "governing_law": "laws of the State of New York",
        "courts": "courts of New York County, New York",
        "non_compete_note": "Non-compete restrictions shall be limited to twelve (12) months post-termination.",
        "arbitration_provider": "AAA",
    },
    "US-DE": {
        "governing_law": "laws of the State of Delaware",
        "courts": "Court of Chancery of the State of Delaware",
        "non_compete_note": "Non-compete provisions shall be limited in geographic scope and duration.",
        "arbitration_provider": "AAA",
    },
    "UK": {
        "governing_law": "laws of England and Wales",
        "courts": "courts of England and Wales",
        "non_compete_note": "Restrictive covenants must be reasonable in scope to be enforceable.",
        "arbitration_provider": "LCIA",
    },
    "EU-DE": {
        "governing_law": "laws of Germany",
        "courts": "courts of Frankfurt am Main",
        "non_compete_note": "Post-contractual non-compete requires compensation under German law.",
        "arbitration_provider": "DIS",
    },
}

# Clause templates keyed by clause type and complexity level
_CLAUSE_LIBRARY: dict[str, dict[str, str]] = {
    "confidentiality": {
        "simple": (
            "Each party agrees to maintain the confidentiality of the other party's "
            "Confidential Information and not to disclose such information to any third party "
            "without prior written consent."
        ),
        "standard": (
            "Each party ('Receiving Party') agrees to: (i) maintain the other party's "
            "Confidential Information in strict confidence using no less than reasonable care; "
            "(ii) not disclose Confidential Information to any third party except as permitted "
            "herein; (iii) use Confidential Information solely for the purposes of this Agreement; "
            "and (iv) promptly notify the Disclosing Party upon discovery of any unauthorized use "
            "or disclosure."
        ),
        "complex": (
            "Each party ('Receiving Party') receiving Confidential Information from the other "
            "party ('Disclosing Party') hereby agrees to: (i) hold all Confidential Information "
            "in strict confidence and protect it with at least the same degree of care used to "
            "protect its own confidential information, but in no event less than reasonable care; "
            "(ii) not use Confidential Information for any purpose other than to evaluate and "
            "carry out the transactions contemplated by this Agreement; (iii) limit disclosure to "
            "employees, officers, and contractors with a need to know who are bound by written "
            "confidentiality obligations no less protective than this Agreement; (iv) immediately "
            "notify the Disclosing Party in writing upon becoming aware of any unauthorized access, "
            "use, or disclosure; and (v) upon request or termination, promptly return or certify "
            "destruction of all Confidential Information."
        ),
    },
    "limitation_of_liability": {
        "simple": (
            "IN NO EVENT SHALL EITHER PARTY BE LIABLE FOR INDIRECT, INCIDENTAL, OR CONSEQUENTIAL "
            "DAMAGES ARISING OUT OF THIS AGREEMENT."
        ),
        "standard": (
            "IN NO EVENT SHALL EITHER PARTY BE LIABLE TO THE OTHER FOR ANY INDIRECT, INCIDENTAL, "
            "SPECIAL, CONSEQUENTIAL, EXEMPLARY, OR PUNITIVE DAMAGES, INCLUDING LOSS OF PROFITS, "
            "DATA, BUSINESS, OR GOODWILL, ARISING OUT OF OR RELATED TO THIS AGREEMENT, REGARDLESS "
            "OF THE THEORY OF LIABILITY AND WHETHER OR NOT ADVISED OF THEIR POSSIBILITY. "
            "EACH PARTY'S AGGREGATE LIABILITY SHALL NOT EXCEED THE AMOUNTS PAID OR PAYABLE "
            "UNDER THIS AGREEMENT IN THE TWELVE MONTHS PRECEDING THE CLAIM."
        ),
        "complex": (
            "EXCEPT FOR (A) BREACHES OF CONFIDENTIALITY OBLIGATIONS, (B) INDEMNIFICATION "
            "OBLIGATIONS, OR (C) GROSS NEGLIGENCE OR WILLFUL MISCONDUCT: (I) IN NO EVENT SHALL "
            "EITHER PARTY BE LIABLE FOR INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, PUNITIVE, "
            "OR EXEMPLARY DAMAGES OF ANY KIND, INCLUDING LOSS OF REVENUE, PROFITS, DATA, "
            "BUSINESS, OR GOODWILL, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES; AND "
            "(II) EACH PARTY'S TOTAL CUMULATIVE LIABILITY ARISING OUT OF OR RELATED TO THIS "
            "AGREEMENT SHALL NOT EXCEED THE GREATER OF (A) THE TOTAL AMOUNTS PAID UNDER THIS "
            "AGREEMENT IN THE TWELVE (12) MONTHS PRECEDING THE EVENT GIVING RISE TO LIABILITY, "
            "OR (B) ONE HUNDRED THOUSAND DOLLARS ($100,000)."
        ),
    },
    "governing_law": {
        "simple": "This Agreement shall be governed by the laws of {governing_law}.",
        "standard": (
            "This Agreement shall be governed by and construed in accordance with the {governing_law}, "
            "without regard to its conflict of law provisions. Any disputes shall be submitted to the "
            "exclusive jurisdiction of {courts}."
        ),
        "complex": (
            "This Agreement shall be governed by and interpreted in accordance with the {governing_law}, "
            "without giving effect to any choice or conflict of law provision or rule. Each party "
            "irrevocably submits to the exclusive jurisdiction of {courts} for resolution of any "
            "dispute arising under or in connection with this Agreement, and waives any objection "
            "to such jurisdiction on grounds of venue, inconvenience, or otherwise. The U.N. "
            "Convention on Contracts for the International Sale of Goods shall not apply."
        ),
    },
}

_COMPANY_NAMES: list[str] = [
    "Acme Solutions Inc.", "Nexus Technologies LLC", "Apex Dynamics Corp.",
    "Meridian Consulting Group", "Stratus Systems Ltd.", "Pinnacle Ventures Inc.",
    "Orion Global Services", "Zenith Data Partners", "Atlas Innovation Corp.",
    "Vega Software Group LLC", "Celsius Analytics Inc.", "Helix Robotics Ltd.",
]

_INDIVIDUAL_NAMES: list[str] = [
    "Alexandra Chen", "Marcus Johnson", "Priya Patel", "David Williams",
    "Sofia Martinez", "James Thompson", "Aisha Okonkwo", "Ryan Mueller",
    "Camille Dubois", "Ethan Park", "Natalia Volkov", "Omar Hassan",
]


class ContractSynthesizer:
    """Generates synthetic legal contracts for training and testing.

    Produces realistic legal documents across multiple contract types with
    parameterized parties, jurisdiction-specific language, configurable
    complexity levels, and full section assembly.
    """

    def __init__(self, default_jurisdiction: str = "US-NY") -> None:
        """Initialize the contract synthesizer.

        Args:
            default_jurisdiction: Default jurisdiction when none specified.
        """
        self._default_jurisdiction = default_jurisdiction
        logger.info("ContractSynthesizer initialized", default_jurisdiction=default_jurisdiction)

    def list_contract_types(self) -> list[str]:
        """Return all supported contract types.

        Returns:
            List of contract type identifiers (NDA, MSA, SLA, EMPLOYMENT, VENDOR).
        """
        return list(_CONTRACT_TEMPLATES.keys())

    def list_jurisdictions(self) -> list[str]:
        """Return all supported jurisdiction codes.

        Returns:
            List of jurisdiction code strings.
        """
        return list(_JURISDICTION_ADAPTATIONS.keys())

    def generate_party(self, party_type: str = "company") -> dict[str, str]:
        """Generate a synthetic party (company or individual).

        Args:
            party_type: "company" or "individual".

        Returns:
            Dict with name, address, and signatory fields.
        """
        if party_type == "individual":
            name = random.choice(_INDIVIDUAL_NAMES)
            return {
                "name": name,
                "address": self._generate_address(),
                "signatory": name,
                "title": random.choice(["Executive", "Director", "Manager"]),
            }
        name = random.choice(_COMPANY_NAMES)
        return {
            "name": name,
            "address": self._generate_address(),
            "signatory": random.choice(_INDIVIDUAL_NAMES),
            "title": random.choice(["CEO", "CFO", "VP Legal", "General Counsel", "COO"]),
        }

    def _generate_address(self) -> str:
        """Generate a plausible US business address."""
        streets = ["Market St", "Broadway", "Technology Dr", "Innovation Blvd", "Commerce Way"]
        cities = [
            ("San Francisco", "CA", "94105"),
            ("New York", "NY", "10001"),
            ("Chicago", "IL", "60601"),
            ("Austin", "TX", "78701"),
            ("Seattle", "WA", "98101"),
        ]
        num = random.randint(100, 9999)
        street = random.choice(streets)
        city, state, zipcode = random.choice(cities)
        return f"{num} {street}, {city}, {state} {zipcode}"

    def _generate_amount(
        self, min_amount: int = 10000, max_amount: int = 5000000
    ) -> str:
        """Generate a formatted dollar amount."""
        amount = random.randint(min_amount // 1000, max_amount // 1000) * 1000
        return f"${amount:,}"

    def _generate_effective_date(self, offset_days: int = 0) -> str:
        """Generate a contract effective date."""
        base_date = date.today() + timedelta(days=offset_days)
        return base_date.strftime("%B %d, %Y")

    def _generate_term_clause(self, contract_type: str, complexity: str) -> str:
        """Generate a term/duration clause for the contract."""
        terms = {
            "NDA": (12, 60),
            "MSA": (12, 36),
            "SLA": (12, 24),
            "EMPLOYMENT": (12, 24),
            "VENDOR": (6, 24),
        }
        min_months, max_months = terms.get(contract_type, (12, 24))
        months = random.randint(min_months, max_months)
        if complexity == "complex":
            return (
                f"This Agreement shall commence on the Effective Date and continue for an "
                f"initial term of {months} months (the 'Initial Term'), unless earlier terminated "
                f"in accordance with the provisions hereof. Upon expiration of the Initial Term, "
                f"this Agreement shall automatically renew for successive one (1) year periods "
                f"unless either party provides written notice of non-renewal not less than sixty "
                f"(60) days prior to the end of the then-current term."
            )
        return (
            f"This Agreement shall commence on the Effective Date and remain in effect for "
            f"{months} months, unless terminated earlier by either party upon thirty (30) "
            f"days' written notice."
        )

    def synthesize_contract(
        self,
        contract_type: str,
        party_a: dict[str, str] | None = None,
        party_b: dict[str, str] | None = None,
        jurisdiction: str | None = None,
        complexity: str = "standard",
        effective_date_offset_days: int = 0,
        contract_value: str | None = None,
        include_optional_sections: bool = True,
        output_format: str = "plain_text",
    ) -> dict[str, Any]:
        """Synthesize a complete synthetic legal contract.

        Args:
            contract_type: Contract type key (NDA, MSA, SLA, EMPLOYMENT, VENDOR).
            party_a: Party A details dict; auto-generated if None.
            party_b: Party B details dict; auto-generated if None.
            jurisdiction: Jurisdiction code; defaults to instance default.
            complexity: Clause complexity level (simple, standard, complex).
            effective_date_offset_days: Days from today for effective date.
            contract_value: Contract value string; auto-generated if None.
            include_optional_sections: Whether to include optional sections.
            output_format: Output format (plain_text, structured).

        Returns:
            Dict with contract_id, metadata, sections, and assembled text.

        Raises:
            ValueError: If contract_type or jurisdiction is unsupported.
        """
        if contract_type not in _CONTRACT_TEMPLATES:
            raise ValueError(
                f"Unsupported contract_type '{contract_type}'. "
                f"Supported: {list(_CONTRACT_TEMPLATES.keys())}"
            )

        jurisdiction = jurisdiction or self._default_jurisdiction
        if jurisdiction not in _JURISDICTION_ADAPTATIONS:
            raise ValueError(
                f"Unsupported jurisdiction '{jurisdiction}'. "
                f"Supported: {list(_JURISDICTION_ADAPTATIONS.keys())}"
            )
        if complexity not in ("simple", "standard", "complex"):
            raise ValueError("complexity must be 'simple', 'standard', or 'complex'")

        contract_id = str(uuid.uuid4())
        template = _CONTRACT_TEMPLATES[contract_type]
        jur = _JURISDICTION_ADAPTATIONS[jurisdiction]

        if party_a is None:
            party_a = self.generate_party("company")
        if party_b is None:
            party_b = self.generate_party(
                "individual" if contract_type == "EMPLOYMENT" else "company"
            )
        if contract_value is None:
            contract_value = self._generate_amount()

        effective_date = self._generate_effective_date(effective_date_offset_days)

        logger.info(
            "Synthesizing contract",
            contract_id=contract_id,
            contract_type=contract_type,
            jurisdiction=jurisdiction,
            complexity=complexity,
        )

        sections: dict[str, str] = {}

        # Header / recitals
        sections["header"] = (
            f"{template['title'].upper()}\n\n"
            f"This {template['title']} (the 'Agreement') is entered into as of {effective_date} "
            f"(the 'Effective Date') by and between {party_a['name']}, with its principal place "
            f"of business at {party_a['address']} ('Party A'), and {party_b['name']}, "
            f"{'residing at' if party_b.get('title') in ('Executive', 'Director', 'Manager') else 'with its principal place of business at'} "
            f"{party_b['address']} ('Party B')."
        )

        # Required sections
        for section_key in template["required_sections"]:
            sections[section_key] = self._build_section(
                section_key=section_key,
                complexity=complexity,
                jur=jur,
                contract_value=contract_value,
                contract_type=contract_type,
            )

        # Optional sections
        if include_optional_sections:
            for section_key in template.get("optional_sections", []):
                if random.random() > 0.4:
                    sections[section_key] = self._build_section(
                        section_key=section_key,
                        complexity=complexity,
                        jur=jur,
                        contract_value=contract_value,
                        contract_type=contract_type,
                    )

        # Term clause
        sections["term"] = self._generate_term_clause(contract_type, complexity)

        # Signature block
        sections["signature_block"] = (
            f"IN WITNESS WHEREOF, the parties have executed this Agreement as of the Effective Date.\n\n"
            f"{party_a['name']}\n"
            f"By: ________________________\n"
            f"Name: {party_a['signatory']}\n"
            f"Title: {party_a['title']}\n\n"
            f"{party_b['name']}\n"
            f"By: ________________________\n"
            f"Name: {party_b['signatory']}\n"
            f"Title: {party_b.get('title', 'Authorized Signatory')}\n"
        )

        assembled_text = self._assemble_document(
            title=template["title"],
            sections=sections,
            output_format=output_format,
        )

        result: dict[str, Any] = {
            "contract_id": contract_id,
            "contract_type": contract_type,
            "jurisdiction": jurisdiction,
            "complexity": complexity,
            "party_a": party_a,
            "party_b": party_b,
            "effective_date": effective_date,
            "contract_value": contract_value,
            "sections": sections,
            "section_count": len(sections),
            "output_format": output_format,
            "assembled_text": assembled_text,
            "word_count": len(assembled_text.split()),
        }

        logger.info(
            "Contract synthesized",
            contract_id=contract_id,
            section_count=len(sections),
            word_count=result["word_count"],
        )

        return result

    def _build_section(
        self,
        section_key: str,
        complexity: str,
        jur: dict[str, str],
        contract_value: str,
        contract_type: str,
    ) -> str:
        """Build a single contract section from the clause library.

        Args:
            section_key: The section identifier key.
            complexity: Clause complexity level.
            jur: Jurisdiction adaptation dict.
            contract_value: Formatted contract value string.
            contract_type: Contract type for context.

        Returns:
            Formatted section text.
        """
        if section_key in _CLAUSE_LIBRARY:
            text = _CLAUSE_LIBRARY[section_key].get(
                complexity, _CLAUSE_LIBRARY[section_key]["standard"]
            )
            # Substitute jurisdiction tokens
            text = text.format(
                governing_law=jur.get("governing_law", "applicable law"),
                courts=jur.get("courts", "courts of competent jurisdiction"),
            )
            return text

        # Generic section generator for sections not in clause library
        section_title = section_key.replace("_", " ").title()
        return (
            f"[Section: {section_title}] The parties agree to the terms and conditions "
            f"governing {section_title.lower()} as set forth herein, in accordance with "
            f"{jur.get('governing_law', 'applicable law')} and the total consideration "
            f"of {contract_value}."
        )

    def _assemble_document(
        self,
        title: str,
        sections: dict[str, str],
        output_format: str,
    ) -> str:
        """Assemble individual sections into a coherent document.

        Args:
            title: Contract title.
            sections: Ordered dict of section key -> text.
            output_format: "plain_text" or "structured".

        Returns:
            Full assembled contract text.
        """
        if output_format == "structured":
            parts = [f"=== {title.upper()} ===\n"]
            for idx, (key, text) in enumerate(sections.items(), start=1):
                heading = key.replace("_", " ").title()
                parts.append(f"\nSection {idx}. {heading}\n{text}\n")
            return "\n".join(parts)

        # Plain text format
        parts = [f"{title.upper()}\n{'=' * len(title)}\n"]
        for key, text in sections.items():
            if key == "header":
                parts.append(f"\n{text}\n")
            elif key == "signature_block":
                parts.append(f"\n{text}")
            else:
                heading = key.replace("_", " ").upper()
                parts.append(f"\n{heading}\n{text}\n")
        return "\n".join(parts)

    def generate_batch(
        self,
        contract_type: str,
        count: int,
        jurisdiction: str | None = None,
        complexity: str = "standard",
    ) -> list[dict[str, Any]]:
        """Generate a batch of synthetic contracts.

        Args:
            contract_type: Contract type key.
            count: Number of contracts to generate.
            jurisdiction: Jurisdiction code; randomized per contract if None.
            complexity: Clause complexity level.

        Returns:
            List of synthesized contract dicts.
        """
        results: list[dict[str, Any]] = []
        jurisdictions = list(_JURISDICTION_ADAPTATIONS.keys())

        for i in range(count):
            jur = jurisdiction or random.choice(jurisdictions)
            contract = self.synthesize_contract(
                contract_type=contract_type,
                jurisdiction=jur,
                complexity=complexity,
                effective_date_offset_days=random.randint(-30, 90),
            )
            results.append(contract)

        logger.info(
            "Batch contract synthesis complete",
            contract_type=contract_type,
            count=count,
            complexity=complexity,
        )
        return results


__all__ = ["ContractSynthesizer"]
