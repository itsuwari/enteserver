
from __future__ import annotations
import os
from pydantic_settings import BaseSettings
from pydantic import Field

class Settings(BaseSettings):
    app_name: str = "Museum‑subset (FastAPI)"
    
    # JWT Configuration
    jwt_secret: str = Field(default=os.environ.get("JWT_SECRET", "dev-secret"))
    jwt_issuer: str = "museum-subset"
    jwt_exp_hours: int = int(os.environ.get("JWT_EXP_HOURS", "24"))
    
    # Admin Configuration
    admin_email: str = os.environ.get("ADMIN_EMAIL", "admin@example.com")
    admin_password: str = os.environ.get("ADMIN_PASSWORD", "changeme")
    
    # Database Configuration
    database_url: str = os.environ.get("DATABASE_URL", "sqlite:///./museum.db")
    
    # S3 / MinIO Configuration
    s3_enabled: bool = bool(int(os.environ.get("S3_ENABLED", "1")))
    s3_endpoint_url: str = os.environ.get("S3_ENDPOINT_URL", "http://localhost:9000")
    s3_region: str = os.environ.get("S3_REGION", "us-east-1")
    s3_access_key: str = os.environ.get("S3_ACCESS_KEY", "minioadmin")
    s3_secret_key: str = os.environ.get("S3_SECRET_KEY", "minioadmin")
    s3_bucket: str = os.environ.get("S3_BUCKET", "ente-objects")
    s3_use_path_style: bool = bool(int(os.environ.get("S3_USE_PATH_STYLE", "1")))
    s3_presign_expiry: int = int(os.environ.get("S3_PRESIGN_EXPIRY", "3600"))
    
    # Multi-cloud S3 buckets (for Ente compatibility)
    s3_b2_eu_cen_bucket: str = os.environ.get("S3_B2_EU_CEN_BUCKET", "ente-b2-eu-cen")
    s3_wasabi_eu_central_bucket: str = os.environ.get("S3_WASABI_EU_CENTRAL_BUCKET", "ente-wasabi-eu")
    s3_scw_eu_fr_bucket: str = os.environ.get("S3_SCW_EU_FR_BUCKET", "ente-scw-eu")
    
    # App Endpoints (Ente compatibility)
    albums_base_url: str = os.environ.get("ALBUMS_BASE_URL", "http://localhost:3002")
    cast_base_url: str = os.environ.get("CAST_BASE_URL", "http://localhost:3003")
    accounts_base_url: str = os.environ.get("ACCOUNTS_BASE_URL", "http://localhost:3001")
    
    # Email Configuration
    smtp_host: str = os.environ.get("SMTP_HOST", "")
    smtp_port: int = int(os.environ.get("SMTP_PORT", "587"))
    smtp_username: str = os.environ.get("SMTP_USERNAME", "")
    smtp_password: str = os.environ.get("SMTP_PASSWORD", "")
    smtp_from_email: str = os.environ.get("SMTP_FROM_EMAIL", "")
    smtp_from_name: str = os.environ.get("SMTP_FROM_NAME", "Ente")
    
    # Encryption Keys (Ente compatibility)
    key_encryption: str = os.environ.get("KEY_ENCRYPTION", "dev-encryption-key")
    key_hash: str = os.environ.get("KEY_HASH", "dev-hash-key")
    
    # Accounts JWT for WebView bridge
    accounts_jwt_secret: str = os.environ.get("ACCOUNTS_JWT_SECRET", "")
    accounts_jwt_iss: str = os.environ.get("ACCOUNTS_JWT_ISS", "museum")
    accounts_jwt_aud: str = os.environ.get("ACCOUNTS_JWT_AUD", "ente-accounts")
    accounts_jwt_ttl_sec: int = int(os.environ.get("ACCOUNTS_JWT_TTL_SEC", "900"))
    
    # Feature Flags
    enable_email_verification: bool = bool(int(os.environ.get("ENABLE_EMAIL_VERIFICATION", "0")))
    enable_public_sharing: bool = bool(int(os.environ.get("ENABLE_PUBLIC_SHARING", "1")))
    enable_family_plans: bool = bool(int(os.environ.get("ENABLE_FAMILY_PLANS", "0")))
    
    # Rate Limiting
    rate_limit_enabled: bool = bool(int(os.environ.get("RATE_LIMIT_ENABLED", "1")))
    rate_limit_requests_per_minute: int = int(os.environ.get("RATE_LIMIT_REQUESTS_PER_MINUTE", "60"))

settings = Settings()
