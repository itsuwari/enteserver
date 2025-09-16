from __future__ import annotations

from pydantic import BaseModel, Field


class Settings(BaseModel):
    app_name: str = "Museum‑subset (FastAPI)"

    # JWT Configuration
    jwt_secret: str = "dev-secret"
    jwt_issuer: str = "museum-subset"
    jwt_exp_hours: int = 24

    # Admin Configuration
    admin_email: str = "admin@example.com"
    admin_password: str = "changeme"

    # Database Configuration
    # Use a simple SQLite file by default; override via `database_url` in config or env
    database_url: str = "sqlite:///./ente.db"

    # S3 / MinIO Configuration
    s3_enabled: bool = True
    s3_endpoint_url: str = "http://localhost:9000"
    s3_region: str = "us-east-1"
    s3_access_key: str = "minioadmin"
    s3_secret_key: str = "minioadmin"
    s3_bucket: str | None = None
    s3_use_path_style: bool = True
    s3_presign_expiry: int = 3600

    # Dynamic multi-backend configuration
    s3_backends: dict[str, dict[str, str]] = Field(default_factory=dict)

    # App Endpoints (Ente compatibility)
    albums_base_url: str = "http://localhost:3002"
    cast_base_url: str = "http://localhost:3003"
    accounts_base_url: str = "http://localhost:3001"

    # Email Configuration
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""
    smtp_from_name: str = "Ente"

    # Encryption Keys (Ente compatibility)
    key_encryption: str = "dev-encryption-key"
    key_hash: str = "dev-hash-key"

    # Accounts JWT for WebView bridge
    accounts_jwt_secret: str = ""
    accounts_jwt_iss: str = "museum"
    accounts_jwt_aud: str = "ente-accounts"
    accounts_jwt_ttl_sec: int = 900

    # Feature Flags
    enable_email_verification: bool = False
    enable_public_sharing: bool = True
    enable_family_plans: bool = False

    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 60
