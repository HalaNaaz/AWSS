import os
from typing import List, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    APP_NAME: str = "Ashlynx WebSec Scanner"
    APP_VERSION: str = "2.0.0-dev"
    SECRET_KEY: str = "insecure-dev-secret-key-change-in-production"
    API_PREFIX: str = "/api/v1"

    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, str) and v.startswith("["):
            import json
            return json.loads(v)
        return v

    # PostgreSQL Database
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "ashlynx_websec"
    POSTGRES_USER: str = "ashlynx_user"
    POSTGRES_PASSWORD: str = "ashlynx_secure_password"
    DATABASE_URL: str = "postgresql+asyncpg://ashlynx_user:ashlynx_secure_password@localhost:5432/ashlynx_websec"

    # Redis Cache & Queue
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_URL: str = "redis://localhost:6379/0"

    # Scanner Egress & Security Gate
    MAX_CONCURRENT_REQUESTS: int = 10
    DEFAULT_REQUEST_TIMEOUT: float = 15.0
    SCANNER_USER_AGENT: str = "Ashlynx-WebSec-Scanner/2.0 (+https://ashlynxcyber.in/security-scanner)"
    STRICT_SSRF_PROTECTION: bool = True
    ALLOW_PRIVATE_IPS: bool = False
    RATE_LIMIT_RPS: float = 10.0

    # Evidence & Cryptography
    EVIDENCE_ENCRYPTION_KEY: str = "32-byte-base64-encoded-aes-gcm-master-key"
    EVIDENCE_RETENTION_DAYS: int = 90


settings = Settings()
