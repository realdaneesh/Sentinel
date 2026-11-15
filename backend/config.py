"""Application configuration loaded from environment variables."""

from pathlib import Path
from typing import Literal
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
    SECRET_KEY: str = "sentinel-insecure-development-secret-key-change-me-32chars"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Detection & Correlation
    DETECTOR_VERSION: str = "1.0.0"
    DEFAULT_CORRELATION_WINDOW_MINUTES: int = 15
    BURST_THRESHOLD: int = 5
    BURST_WINDOW_MINUTES: int = 15
    MIN_HISTORY_FOR_NOVELTY: int = 1


settings = Settings()

