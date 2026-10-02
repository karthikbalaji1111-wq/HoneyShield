from __future__ import annotations

from functools import lru_cache
from typing import Literal, Optional

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


class Settings(BaseSettings):
    app_name: str = "HoneyShield"
    app_version: str = "0.1.0"
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"
    log_level: str = "INFO"

    database_url: Optional[str] = None
    postgres_db: str = "honeyshield_dev"
    postgres_user: str = "honeyshield"
    postgres_password: str = Field(default="honeyshield_dev_password", repr=False)
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    
    db_pool_size: int = Field(default=10, ge=1, le=50)
    db_max_overflow: int = Field(default=10, ge=0, le=50)
    db_pool_timeout: float = Field(default=10.0, ge=1.0, le=60.0)
    db_pool_recycle: int = Field(default=1800, ge=60, le=7200)
    db_statement_timeout_ms: int = Field(default=5000, ge=500, le=60000)
    db_analytics_timeout_ms: int = Field(default=15000, ge=1000, le=120000)

    jwt_secret_key: str = Field(repr=False)
    jwt_algorithm: Literal["HS256"] = "HS256"
    access_token_expire_minutes: int = Field(default=30, ge=1, le=1440)
    login_attempts_per_minute: int = Field(default=30, ge=1, le=1000)
    login_global_attempts_per_minute: int = Field(default=600, ge=1, le=10000)

    @field_validator("jwt_secret_key")
    @classmethod
    def validate_signing_key(cls, value: str) -> str:
        if len(value.encode("utf-8")) < 32 or value != value.strip() or not value.strip():
            raise ValueError("JWT_SECRET_KEY must contain at least 32 bytes without surrounding whitespace")
        return value

    @model_validator(mode="after")
    def validate_production_configuration(self) -> Settings:
        if self.app_env.lower() in ("production", "prod", "staging"):
            if not self.database_url:
                if not self.postgres_password or self.postgres_password == "honeyshield_dev_password":
                    raise ValueError("POSTGRES_PASSWORD must be explicitly configured in production")
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        hide_input_in_errors=True,
    )

    @property
    def sqlalchemy_database_uri(self) -> str:
        if self.database_url:
            return self.database_url

        return URL.create(
            "postgresql+psycopg2",
            username=self.postgres_user,
            password=self.postgres_password,
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        ).render_as_string(hide_password=False)


@lru_cache
def get_settings() -> Settings:
    return Settings()
