"""Configuration for Payload Service."""
import os
from pathlib import Path


class Settings:
    """Application settings from environment variables."""

    # Server settings
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://relay:relay@relay-db:5432/relay"
    )

    # Storage
    STORAGE_PATH: Path = Path(os.getenv("STORAGE_PATH", "/payloads"))

    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # Service info
    SERVICE_NAME: str = "payload-service"
    VERSION: str = "1.0.0"


settings = Settings()
