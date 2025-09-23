
from __future__ import annotations
import datetime as dt
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from .db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False, index=True)

    # SRP authentication (Ente-compatible)
    srp_user_id = Column(String, nullable=True)  # SRP user identifier (usually email)
    srp_salt = Column(String, nullable=True)  # SRP salt used in verifier generation
    srp_verifier = Column(String, nullable=True)  # SRP verifier for zero-knowledge auth
    kek_salt = Column(String, nullable=True)  # Key encryption key salt
    mem_limit = Column(Integer, default=67108864)  # Argon2 memory limit (64MB default)
    ops_limit = Column(Integer, default=3)  # Argon2 operations limit
    is_email_mfa_enabled = Column(Boolean, default=False)  # Email MFA status

    # Legacy password support (remove after SRP migration)
    password_hash = Column(String, nullable=True)

    # Encryption keys for E2EE
    encrypted_master_key = Column(Text, nullable=True)
    master_key_recovery_key = Column(Text, nullable=True)
    public_key = Column(Text, nullable=True)
    encrypted_private_key = Column(Text, nullable=True)
    
    # User metadata
    is_email_verified = Column(Boolean, default=False)
    email_verification_token = Column(String, nullable=True)
    
    # Storage quota and usage (in bytes)
    storage_quota = Column(Integer, default=10737418240)  # 10GB default
    storage_used = Column(Integer, default=0)  # Current usage
    storage_bonus = Column(Integer, default=0)  # Bonus storage from referrals, etc.
    
    # Subscription and billing
    subscription_type = Column(String, default="free")  # free, paid, family
    subscription_expires_at = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

class Collection(Base):
    __tablename__ = "collections"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    
    # Collection encryption and metadata
    encrypted_key = Column(Text, nullable=True)
    key_decryption_nonce = Column(Text, nullable=True)
    encrypted_name = Column(Text, nullable=True)
    name_decryption_nonce = Column(Text, nullable=True)
    
    # Collection type and attributes
    collection_type = Column(String, nullable=True)  # album, folder, etc.
    is_shared = Column(Boolean, default=False)
    is_pinned = Column(Boolean, default=False)
    
    # Magic metadata for collections
    magic_metadata_header = Column(Text, nullable=True)
    magic_metadata_data = Column(Text, nullable=True)
    magic_metadata_version = Column(Integer, nullable=True)
    
    # Public magic metadata
    pub_magic_metadata_header = Column(Text, nullable=True)
    pub_magic_metadata_data = Column(Text, nullable=True)
    pub_magic_metadata_version = Column(Integer, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

class File(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    collection_id = Column(Integer, ForeignKey("collections.id"), nullable=True)

    file_object_key = Column(String, nullable=False)
    thumbnail_object_key = Column(String, nullable=True)

    encrypted_key = Column(Text, nullable=True)
    key_decryption_nonce = Column(Text, nullable=True)

    metadata_header = Column(Text, nullable=True)
    metadata_encrypted_data = Column(Text, nullable=True)

    magic_metadata_header = Column(Text, nullable=True)
    magic_metadata_data = Column(Text, nullable=True)
    magic_metadata_version = Column(Integer, nullable=True)
    
    # Public magic metadata for shared collections
    pub_magic_metadata_header = Column(Text, nullable=True)
    pub_magic_metadata_data = Column(Text, nullable=True)
    pub_magic_metadata_version = Column(Integer, nullable=True)
    pub_magic_metadata_count = Column(Integer, nullable=True)

    mime_type = Column(String, nullable=True)
    size = Column(Integer, nullable=True)
    sha256 = Column(String, nullable=True)
    original_filename = Column(String, nullable=True)
    
    # Additional compatibility fields
    etag = Column(String, nullable=True)
    file_nonce = Column(Text, nullable=True)
    thumbnail_nonce = Column(Text, nullable=True)
    
    # Storage tier tracking (primary, secondary, cold)
    storage_tier = Column(String, default="primary", nullable=False)
    is_replica = Column(Boolean, default=False)  # True for replicated files

    is_trashed = Column(Boolean, default=False)
    trashed_at = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

class PublicCollectionLink(Base):
    __tablename__ = "public_collection_links"
    id = Column(Integer, primary_key=True)
    token = Column(String, unique=True, index=True)
    collection_id = Column(Integer, ForeignKey("collections.id"), nullable=False)
    allow_upload = Column(Boolean, default=False)
    password_hash = Column(String, nullable=True)
    expires_at = Column(DateTime, nullable=True)

class PublicFileLink(Base):
    __tablename__ = "public_file_links"
    id = Column(Integer, primary_key=True)
    token = Column(String, unique=True, index=True)
    file_id = Column(Integer, ForeignKey("files.id"), nullable=False)
    password_hash = Column(String, nullable=True)
    expires_at = Column(DateTime, nullable=True)

class KexRecord(Base):
    __tablename__ = "kex_records"
    id = Column(Integer, primary_key=True)
    identifier = Column(String, unique=True, index=True)
    wrapped_key = Column(Text, nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    consumed = Column(Boolean, default=False)

class UserSession(Base):
    __tablename__ = "user_sessions"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    jti = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    last_seen_at = Column(DateTime, default=dt.datetime.utcnow)
    ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    client_package = Column(String, nullable=True)
    client_version = Column(String, nullable=True)
    revoked = Column(Boolean, default=False)


class UserInvite(Base):
    __tablename__ = "user_invites"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    token = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    consumed = Column(Boolean, default=False)


class OneTimeToken(Base):
    """
    OTT (One-Time-Token) for email verification during signup/login
    Compatible with Ente mobile clients
    """
    __tablename__ = "one_time_tokens"
    id = Column(Integer, primary_key=True)
    email = Column(String, nullable=False, index=True)
    ott = Column(String, nullable=False)  # 6-digit code
    purpose = Column(String, nullable=True)  # "signup", "login", "change", etc.
    attempts = Column(Integer, default=0)  # Rate limiting
    max_attempts = Column(Integer, default=3)
    is_used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)  # Usually 10 minutes from creation


class SRPSession(Base):
    """
    SRP session storage for proper SRP-6a protocol implementation
    Compatible with Ente mobile clients
    """
    __tablename__ = "srp_sessions" 
    id = Column(Integer, primary_key=True)
    session_id = Column(String, unique=True, nullable=False, index=True)
    setup_id = Column(String, unique=True, nullable=True, index=True)  # For setup flow
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    srp_user_id = Column(String, nullable=False)  # Usually email
    srp_a = Column(String, nullable=False)  # Client's public ephemeral value
    srp_b = Column(String, nullable=False)  # Server's public ephemeral value  
    srp_b_private = Column(String, nullable=False)  # Server's private ephemeral value
    srp_s = Column(String, nullable=True)  # Shared secret (computed during verification)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)  # Usually 5 minutes from creation
