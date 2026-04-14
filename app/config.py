from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")

    # ── Application ──────────────────────────────────────────────────────────
    APP_NAME: str = "Bionex API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # ── JWT ───────────────────────────────────────────────────────────────────
    SECRET_KEY: str = ""  # MUST be set in production
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── Sharing sessions (NFC / Bluetooth) ────────────────────────────────────
    SHARING_TOKEN_EXPIRE_MINUTES: int = 30

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql://bionex:bionex@localhost:5432/bionex"

    # ── Field-level encryption (Fernet key) ───────────────────────────────────
    # Generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    FIELD_ENCRYPTION_KEY: str = ""

    # ── Redis ─────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── CORS — comma-separated origins ────────────────────────────────────────
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:8080"

    # ── Rate limiting ─────────────────────────────────────────────────────────
    RATE_LIMIT_AUTH: str = "30/minute"
    RATE_LIMIT_DEFAULT: str = "1000/minute"

    @property
    def allowed_origins_list(self) -> List[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    def validate_config(self) -> None:
        """Validate critical configuration settings."""
        if not self.SECRET_KEY or self.SECRET_KEY == "change-me-in-production":
            raise ValueError(
                "ERROR: SECRET_KEY must be configured in .env file. "
                "It must be a strong random string (min 32 characters). "
                "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )
        if not self.DEBUG and not self.FIELD_ENCRYPTION_KEY:
            raise ValueError(
                "ERROR: FIELD_ENCRYPTION_KEY must be configured in production. "
                "Generate with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )


@lru_cache()
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_config()
    return settings
