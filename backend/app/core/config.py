from __future__ import annotations

from functools import lru_cache
from typing import Any, Literal, Optional, Union
import json
import urllib.parse

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

    # Phase 7 — Input Security & Rate Limiting Settings
    max_request_body_bytes: int = Field(default=1_048_576, ge=1024, le=52_428_800)  # Default: 1 MB
    rate_limit_enabled: bool = Field(default=True)
    rate_limit_per_minute_authenticated: int = Field(default=300, ge=1, le=10000)
    rate_limit_per_minute_public: int = Field(default=120, ge=1, le=10000)
    rate_limit_global_per_minute: int = Field(default=5000, ge=10, le=100000)
    ingestion_rate_limit_per_minute_ip: int = Field(default=120, ge=1, le=10000)
    ingestion_rate_limit_per_minute_token: int = Field(default=60, ge=1, le=10000)

    # Phase 7 — Header Security Settings
    header_max_key_length: int = Field(default=64, ge=8, le=256)
    header_max_value_length: int = Field(default=1024, ge=16, le=8192)
    header_max_count: int = Field(default=30, ge=5, le=100)
    header_max_total_bytes: int = Field(default=4096, ge=512, le=32768)

    # Phase 7 — Trusted Proxy Settings
    trusted_proxies: Union[list[str], str] = Field(default_factory=lambda: ["127.0.0.1", "::1"])

    # Phase 11 — CORS Policy Settings (F-014)
    cors_allowed_origins: Union[list[str], str] = Field(default_factory=list)
    cors_allow_credentials: bool = Field(default=False)
    cors_allow_methods: Union[list[str], str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    )
    cors_allow_headers: Union[list[str], str] = Field(
        default_factory=lambda: ["Authorization", "Content-Type", "Accept", "X-Request-ID"]
    )
    cors_expose_headers: Union[list[str], str] = Field(
        default_factory=lambda: ["X-Request-ID", "X-Process-Time-Ms", "Retry-After"]
    )
    cors_max_age: int = Field(default=600, ge=0, le=86400)

    @field_validator("trusted_proxies", mode="before")
    @classmethod
    def parse_trusted_proxies(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            trimmed = value.strip()
            if trimmed.startswith("[") and trimmed.endswith("]"):
                try:
                    value = json.loads(trimmed)
                except Exception:
                    pass
        if isinstance(value, str):
            return [p.strip() for p in value.split(",") if p.strip()]
        if isinstance(value, (list, tuple, set)):
            return [str(p).strip() for p in value if str(p).strip()]
        return ["127.0.0.1", "::1"]

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def parse_and_validate_cors_origins(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            trimmed = value.strip()
            if trimmed.startswith("[") and trimmed.endswith("]"):
                try:
                    value = json.loads(trimmed)
                except Exception:
                    pass
        raw_list: list[str]
        if isinstance(value, str):
            raw_list = [item.strip() for item in value.split(",") if item.strip()]
        elif isinstance(value, (list, tuple, set)):
            raw_list = [str(item).strip() for item in value if str(item).strip()]
        else:
            raise ValueError(f"Invalid type for cors_allowed_origins: {type(value)}")

        validated_origins: list[str] = []
        for raw in raw_list:
            if raw == "*":
                raise ValueError("Wildcard '*' CORS origins are strictly forbidden")
            if "*" in raw:
                raise ValueError(f"Wildcard patterns are forbidden in CORS origins: {raw}")

            parsed = urllib.parse.urlsplit(raw)
            scheme = parsed.scheme.lower()
            if scheme not in ("http", "https"):
                raise ValueError(
                    f"Invalid CORS origin scheme '{parsed.scheme}': only http and https are permitted ({raw})"
                )

            netloc = parsed.netloc.lower()
            if not netloc or not parsed.hostname:
                raise ValueError(f"Invalid CORS origin: missing host ({raw})")

            if parsed.username or parsed.password:
                raise ValueError(f"CORS origin must not contain user credentials: {raw}")

            if parsed.path and parsed.path != "/":
                raise ValueError(f"CORS origin must not contain a path component: {raw}")

            if parsed.query:
                raise ValueError(f"CORS origin must not contain query parameters: {raw}")

            if parsed.fragment:
                raise ValueError(f"CORS origin must not contain URL fragments: {raw}")

            canonical_origin = f"{scheme}://{netloc}"
            if canonical_origin not in validated_origins:
                validated_origins.append(canonical_origin)

        return validated_origins

    @field_validator("cors_allow_methods", mode="before")
    @classmethod
    def parse_and_validate_cors_methods(cls, value: Any) -> list[str]:
        if value is None:
            return ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        if isinstance(value, str):
            trimmed = value.strip()
            if trimmed.startswith("[") and trimmed.endswith("]"):
                try:
                    value = json.loads(trimmed)
                except Exception:
                    pass
        raw_list: list[str]
        if isinstance(value, str):
            raw_list = [item.strip() for item in value.split(",") if item.strip()]
        elif isinstance(value, (list, tuple, set)):
            raw_list = [str(item).strip() for item in value if str(item).strip()]
        else:
            raise ValueError(f"Invalid type for cors_allow_methods: {type(value)}")

        allowed_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
        validated_methods: list[str] = []
        for raw in raw_list:
            method = raw.upper()
            if method == "*":
                raise ValueError("Wildcard '*' is forbidden in cors_allow_methods; specify explicit methods")
            if method not in allowed_methods:
                raise ValueError(f"Invalid HTTP method '{method}' in cors_allow_methods")
            if method not in validated_methods:
                validated_methods.append(method)
        return validated_methods or ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

    @field_validator("cors_allow_headers", mode="before")
    @classmethod
    def parse_and_validate_cors_headers(cls, value: Any) -> list[str]:
        if value is None:
            return ["Authorization", "Content-Type", "Accept", "X-Request-ID"]
        if isinstance(value, str):
            trimmed = value.strip()
            if trimmed.startswith("[") and trimmed.endswith("]"):
                try:
                    value = json.loads(trimmed)
                except Exception:
                    pass
        raw_list: list[str]
        if isinstance(value, str):
            raw_list = [item.strip() for item in value.split(",") if item.strip()]
        elif isinstance(value, (list, tuple, set)):
            raw_list = [str(item).strip() for item in value if str(item).strip()]
        else:
            raise ValueError(f"Invalid type for cors_allow_headers: {type(value)}")

        validated_headers: list[str] = []
        for raw in raw_list:
            if raw == "*":
                raise ValueError("Wildcard '*' is forbidden in cors_allow_headers; specify explicit headers")
            if not any(h.lower() == raw.lower() for h in validated_headers):
                validated_headers.append(raw)
        return validated_headers or ["Authorization", "Content-Type", "Accept", "X-Request-ID"]

    @field_validator("cors_expose_headers", mode="before")
    @classmethod
    def parse_and_validate_cors_expose_headers(cls, value: Any) -> list[str]:
        if value is None:
            return ["X-Request-ID", "X-Process-Time-Ms", "Retry-After"]
        if isinstance(value, str):
            trimmed = value.strip()
            if trimmed.startswith("[") and trimmed.endswith("]"):
                try:
                    value = json.loads(trimmed)
                except Exception:
                    pass
        raw_list: list[str]
        if isinstance(value, str):
            raw_list = [item.strip() for item in value.split(",") if item.strip()]
        elif isinstance(value, (list, tuple, set)):
            raw_list = [str(item).strip() for item in value if str(item).strip()]
        else:
            raise ValueError(f"Invalid type for cors_expose_headers: {type(value)}")

        validated_headers: list[str] = []
        for raw in raw_list:
            if raw == "*":
                raise ValueError("Wildcard '*' is forbidden in cors_expose_headers; specify explicit headers")
            if not any(h.lower() == raw.lower() for h in validated_headers):
                validated_headers.append(raw)
        return validated_headers or ["X-Request-ID", "X-Process-Time-Ms", "Retry-After"]

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

    @model_validator(mode="after")
    def validate_cors_credentials(self) -> Settings:
        if self.cors_allow_credentials and "*" in self.cors_allowed_origins:
            raise ValueError("Wildcard origins cannot be used when cors_allow_credentials is True")
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
