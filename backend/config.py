"""Application configuration loaded from environment variables."""

from pathlib import Path
from typing import Literal
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).resolve().parent.parent / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    ENVIRONMENT: Literal["development", "testing", "production"] = "development"
    DEBUG: bool = True
    PROJECT_NAME: str = "Sentinel Platform"
    API_V1_PREFIX: str = "/api/v1"

    # Database
    DATABASE_URL: str = "sqlite:///./sentinel.db"
    DATABASE_ECHO: bool = False

    # Security
    SECRET_KEY: str
    ALGORITHM: Literal["HS256"] = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    SIMULATOR_PERSISTENCE_ENABLED: bool = False

    @model_validator(mode="after")
    def validate_signing_key(self) -> "Settings":
        secret = self.SECRET_KEY
        known_weak = {
            "sentinel-insecure-development-secret-key-change-me-32chars",
            "CHANGE_THIS_IN_PRODUCTION_TO_A_SECURE_RANDOM_SECRET_KEY",
            "REPLACE_WITH_A_RANDOMLY_GENERATED_SIGNING_SECRET",
            "generate-a-secure-random-key-for-production",
        }
        lowered = secret.casefold()
        if (len(secret.encode("utf-8")) < 32 or secret != secret.strip()
                or len(set(secret)) < 12 or secret in known_weak
                or lowered.startswith(("change_this", "replace_with", "test-secret"))
                or (self.ENVIRONMENT == "production" and secret.startswith("test-only-"))):
            # RuntimeError avoids Pydantic's ValidationError input-value echo.
            raise RuntimeError("SECRET_KEY must be an explicit strong signing secret")
        return self

    # Detection & Correlation
    DETECTOR_VERSION: str = "1.0.0"
    DEFAULT_CORRELATION_WINDOW_MINUTES: int = 15
    BURST_THRESHOLD: int = 5
    BURST_WINDOW_MINUTES: int = 15
    MIN_HISTORY_FOR_NOVELTY: int = 1


settings = Settings()

