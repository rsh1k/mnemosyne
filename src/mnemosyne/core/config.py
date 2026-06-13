"""Runtime configuration.

Configuration is environment-driven (12-factor) so the same artifact runs in
dev, CI, and production with no code changes. The integrity key is read from
the environment or an injected secret; a KMS/HSM hook point is provided for
enterprise deployments (see ``integrity.signer.KeyProvider``).
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MNEMOSYNE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Integrity -------------------------------------------------------
    # In production this MUST be supplied via a secret manager, never a literal.
    integrity_key: str = Field(
        default="dev-insecure-key-change-me",
        description="HMAC key for record integrity. Override in all real envs.",
    )
    require_integrity_on_read: bool = Field(
        default=True,
        description="If true, records that fail HMAC verification are rejected.",
    )

    # --- Policy ----------------------------------------------------------
    policy_path: str | None = Field(
        default=None,
        description="Path to a YAML policy file. Falls back to the bundled default.",
    )
    fail_closed: bool = Field(
        default=True,
        description="On internal detector error, deny rather than allow.",
    )

    # --- Detector thresholds --------------------------------------------
    injection_block_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    anomaly_size_bytes: int = Field(default=64_000, ge=0)

    # --- API service -----------------------------------------------------
    api_keys: str = Field(
        default="",
        description="Comma-separated list of accepted bearer API keys.",
    )
    rate_limit_per_minute: int = Field(default=600, ge=0)

    # --- Telemetry -------------------------------------------------------
    log_level: str = Field(default="INFO")
    log_json: bool = Field(default=True)

    def api_key_set(self) -> set[str]:
        return {k.strip() for k in self.api_keys.split(",") if k.strip()}


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return a cached settings singleton."""

    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings_cache() -> None:
    """Test helper to clear the cached settings."""

    global _settings
    _settings = None
