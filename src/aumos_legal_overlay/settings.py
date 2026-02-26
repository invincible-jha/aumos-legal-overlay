"""Service-specific settings for aumos-legal-overlay.

All standard AumOS configuration is inherited from AumOSSettings.
Legal-specific settings use the AUMOS_LEGAL_ env prefix.
"""

from pydantic_settings import SettingsConfigDict

from aumos_common.config import AumOSSettings


class Settings(AumOSSettings):
    """Settings for aumos-legal-overlay.

    Inherits all standard AumOS settings (database, kafka, keycloak, etc.)
    and adds legal-specific configuration.

    Environment variable prefix: AUMOS_LEGAL_
    """

    service_name: str = "aumos-legal-overlay"

    # Privilege preservation settings
    privilege_review_timeout_seconds: int = 3600
    privilege_confidence_threshold: float = 0.85

    # E-discovery settings
    ediscovery_max_document_batch_size: int = 1000
    ediscovery_default_date_range_days: int = 365

    # Audit trail settings
    audit_trail_immutable: bool = True
    audit_trail_hash_algorithm: str = "sha256"

    # Legal hold settings
    legal_hold_notification_interval_days: int = 30
    legal_hold_max_custodians: int = 500

    model_config = SettingsConfigDict(env_prefix="AUMOS_LEGAL_")
