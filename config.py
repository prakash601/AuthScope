"""Typed application settings loaded from environment / .env.

Single source of configuration truth for API, workers, and engine.
Usage: ``from config import get_settings``.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="POSTGRES_", env_file=".env", extra="ignore")

    host: str = "localhost"
    port: int = 5432
    user: str
    password: str
    db: str
    pool_size: int = 10
    max_overflow: int = 20

    @property
    def async_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.db}"
        )

    @property
    def sync_url(self) -> str:
        return (
            f"postgresql://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.db}"
        )


class S3Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="S3_", env_file=".env", extra="ignore")

    endpoint_url: str | None = None
    access_key: str
    secret_key: str
    bucket: str
    region: str = "us-east-1"


class ScanSettings(BaseSettings):
    """Engine limits per README §Production Considerations."""

    model_config = SettingsConfigDict(env_prefix="SCAN_", env_file=".env", extra="ignore")

    timeout_seconds: int = Field(default=45, ge=5, le=300)
    lazy_captcha_wait_seconds: int = Field(default=5, ge=0, le=60)
    context_max_ram_mb: int = 150
    retry_blocked_once: bool = True


class ApiSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="API_", env_file=".env", extra="ignore")

    rate_limit_per_minute: int = 60


class Settings(BaseSettings):
    """Aggregate settings; sub-groups validate their own env vars.

    Flat fields (no prefix) read directly from env: ``REDIS_URL`` etc.
    """

    database: DatabaseSettings = Field(default_factory=lambda: DatabaseSettings())
    s3: S3Settings = Field(default_factory=lambda: S3Settings())
    scan: ScanSettings = Field(default_factory=lambda: ScanSettings())
    api: ApiSettings = Field(default_factory=lambda: ApiSettings())
    redis_url: str = "redis://localhost:6379/0"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
