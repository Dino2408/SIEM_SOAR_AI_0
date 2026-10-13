from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    # --- Database ---
    DB_URL: str = Field(default="postgresql+asyncpg://postgres:postgres@localhost:5432/siemsoar")

    # --- Redis ---
    REDIS_URL: str = Field(default="redis://localhost:6379/0")
    REDIS_HOST: str = Field(default="redis")
    REDIS_PORT: int = Field(default=6379)

    # --- Elasticsearch ---
    ES_URL: str = Field(default="http://localhost:9200")

    # --- AI ---
    GEMINI_API_KEY: str = Field(default="")
    
    # --- Security / JWT ---
    SECRET_KEY: str = Field(default="dev-secret-key-change-in-production")
    ALGORITHM: str = Field(default="HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60)

    # --- Application ---
    DEBUG: bool = Field(default=False)
    LOG_LEVEL: str = Field(default="INFO")
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost", "http://localhost:80", "http://127.0.0.1"]
    )

    # --- Threat Intelligence (optional) ---
    ABUSEIPDB_API_KEY: str = Field(default="")
    VIRUSTOTAL_API_KEY: str = Field(default="")

    # --- Notifications (optional) ---
    SLACK_WEBHOOK_URL: str = Field(default="")
    SMTP_HOST: str = Field(default="")
    SMTP_PORT: int = Field(default=587)
    SMTP_USER: str = Field(default="")
    SMTP_PASSWORD: str = Field(default="")
    SMTP_FROM: str = Field(default="siem@localhost")
    ALERT_EMAIL: str = Field(default="")

    # --- AI Engine ---
    AI_ENGINE_URL: str = Field(default="http://ai-engine:8001")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

settings = Settings()

