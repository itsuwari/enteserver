from __future__ import annotations
import logging
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from .models import User, File
from .db import get_db

logger = logging.getLogger(__name__)

class StorageQuotaExceeded(Exception):
    """Raised when user exceeds storage quota"""
    def __init__(self, used: int, quota: int, requested: int):
        self.used = used
        self.quota = quota
        self.requested = requested
        super().__init__(f"Storage quota exceeded: {used + requested} bytes > {quota} bytes")

def get_user_storage_usage(user_id: int, db: Session) -> dict:
    """Calculate user's current storage usage - only PRIMARY tier files count"""
    # Calculate total size of non-trashed PRIMARY tier files (exclude replicas)
    result = db.query(func.sum(File.size)).filter(
        File.owner_id == user_id,
        File.is_trashed == False,
        File.storage_tier == "primary",
        File.is_replica == False,
        File.size.isnot(None)
    ).scalar()
    
    actual_usage = result or 0
    
    # Get user's stored usage and quota
    user = db.get(User, user_id)
    if not user:
        return {"error": "User not found"}
    
    total_quota = user.storage_quota + user.storage_bonus
    
    return {
        "used": actual_usage,
        "stored_used": user.storage_used,
        "quota": user.storage_quota,
        "bonus": user.storage_bonus,
        "total_quota": total_quota,
        "available": max(0, total_quota - actual_usage),
        "usage_percentage": (actual_usage / total_quota * 100) if total_quota > 0 else 0
    }

def update_user_storage_usage(user_id: int, db: Session) -> dict:
    """Recalculate and update user's storage usage"""
    usage_info = get_user_storage_usage(user_id, db)
    
    if "error" in usage_info:
        return usage_info
    
    # Update stored usage to match actual usage
    user = db.get(User, user_id)
    user.storage_used = usage_info["used"]
    db.commit()
    
    logger.info(f"Updated storage usage for user {user_id}: {usage_info['used']} bytes")
    return usage_info

def check_storage_quota(user_id: int, additional_size: int, db: Session) -> bool:
    """Check if user can upload additional_size bytes without exceeding quota"""
    usage_info = get_user_storage_usage(user_id, db)
    
    if "error" in usage_info:
        return False
    
    return usage_info["used"] + additional_size <= usage_info["total_quota"]

def enforce_storage_quota(user_id: int, file_size: int, db: Session) -> None:
    """Enforce storage quota before file upload"""
    if not check_storage_quota(user_id, file_size, db):
        usage_info = get_user_storage_usage(user_id, db)
        raise StorageQuotaExceeded(
            used=usage_info["used"],
            quota=usage_info["total_quota"],
            requested=file_size
        )

def add_file_to_storage_usage(user_id: int, file_size: int, db: Session) -> None:
    """Add file size to user's storage usage counter"""
    user = db.get(User, user_id)
    if user:
        user.storage_used += file_size
        db.commit()
        logger.info(f"Added {file_size} bytes to user {user_id} storage usage")

def remove_file_from_storage_usage(user_id: int, file_size: int, db: Session) -> None:
    """Remove file size from user's storage usage counter"""
    user = db.get(User, user_id)
    if user:
        user.storage_used = max(0, user.storage_used - file_size)
        db.commit()
        logger.info(f"Removed {file_size} bytes from user {user_id} storage usage")

def set_user_storage_quota(user_id: int, new_quota: int, db: Session) -> bool:
    """Set user's storage quota (admin function)"""
    user = db.get(User, user_id)
    if not user:
        return False
    
    user.storage_quota = new_quota
    db.commit()
    logger.info(f"Set storage quota for user {user_id} to {new_quota} bytes")
    return True

def add_storage_bonus(user_id: int, bonus_bytes: int, db: Session) -> bool:
    """Add bonus storage to user (referrals, promotions, etc.)"""
    user = db.get(User, user_id)
    if not user:
        return False
    
    user.storage_bonus += bonus_bytes
    db.commit()
    logger.info(f"Added {bonus_bytes} bytes bonus storage to user {user_id}")
    return True

def format_storage_size(bytes_size: int) -> str:
    """Format storage size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f} PB"

# Storage tier quotas (for multi-cloud) - Equal replication for all
STORAGE_TIER_LIMITS = {
    "free": {
        "total": 10 * 1024 * 1024 * 1024,  # 10GB
        "primary": 10 * 1024 * 1024 * 1024,  # 10GB
        "secondary": float('inf'),  # Unlimited secondary (replicas)
        "cold": float('inf'),  # Unlimited cold storage (replicas)
    },
    "paid": {
        "total": 100 * 1024 * 1024 * 1024,  # 100GB
        "primary": 100 * 1024 * 1024 * 1024,  # 100GB
        "secondary": float('inf'),  # Unlimited secondary (replicas)
        "cold": float('inf'),  # Unlimited cold storage (replicas)
    },
    "family": {
        "total": 2 * 1024 * 1024 * 1024 * 1024,  # 2TB
        "primary": 2 * 1024 * 1024 * 1024 * 1024,  # 2TB
        "secondary": float('inf'),  # Unlimited secondary (replicas)
        "cold": float('inf'),  # Unlimited cold storage (replicas)
    }
}

def get_tier_quota_for_user(user: User) -> dict:
    """Get storage tier quotas based on user's subscription"""
    return STORAGE_TIER_LIMITS.get(user.subscription_type, STORAGE_TIER_LIMITS["free"])

def get_user_replica_usage(user_id: int, db: Session) -> dict:
    """Get storage usage breakdown by tier including replicas"""
    # Primary tier usage (counts against quota)
    primary_usage = db.query(func.sum(File.size)).filter(
        File.owner_id == user_id,
        File.is_trashed == False,
        File.storage_tier == "primary",
        File.is_replica == False,
        File.size.isnot(None)
    ).scalar() or 0
    
    # Secondary tier usage (replicas, don't count against quota)
    secondary_usage = db.query(func.sum(File.size)).filter(
        File.owner_id == user_id,
        File.is_trashed == False,
        File.storage_tier == "secondary",
        File.size.isnot(None)
    ).scalar() or 0
    
    # Cold tier usage (replicas, don't count against quota)
    cold_usage = db.query(func.sum(File.size)).filter(
        File.owner_id == user_id,
        File.is_trashed == False,
        File.storage_tier == "cold",
        File.size.isnot(None)
    ).scalar() or 0
    
    return {
        "primary_usage": primary_usage,
        "secondary_usage": secondary_usage,
        "cold_usage": cold_usage,
        "total_replicated": secondary_usage + cold_usage,
        "quota_usage": primary_usage  # Only primary counts against quota
    }

def create_replica_file_record(original_file: File, target_tier: str, db: Session) -> File:
    """Create a replica file record for tracking purposes"""
    replica = File(
        owner_id=original_file.owner_id,
        collection_id=original_file.collection_id,
        file_object_key=original_file.file_object_key,
        thumbnail_object_key=original_file.thumbnail_object_key,
        thumbnail_size=original_file.thumbnail_size,
        encrypted_key=original_file.encrypted_key,
        key_decryption_nonce=original_file.key_decryption_nonce,
        metadata_header=original_file.metadata_header,
        metadata_encrypted_data=original_file.metadata_encrypted_data,
        magic_metadata_header=original_file.magic_metadata_header,
        magic_metadata_data=original_file.magic_metadata_data,
        magic_metadata_version=original_file.magic_metadata_version,
        magic_metadata_count=original_file.magic_metadata_count,
        pub_magic_metadata_header=original_file.pub_magic_metadata_header,
        pub_magic_metadata_data=original_file.pub_magic_metadata_data,
        pub_magic_metadata_version=original_file.pub_magic_metadata_version,
        pub_magic_metadata_count=original_file.pub_magic_metadata_count,
        mime_type=original_file.mime_type,
        size=original_file.size,
        sha256=original_file.sha256,
        original_filename=original_file.original_filename,
        etag=original_file.etag,
        file_nonce=original_file.file_nonce,
        thumbnail_nonce=original_file.thumbnail_nonce,
        storage_tier=target_tier,
        is_replica=True
    )
    
    db.add(replica)
    db.commit()
    db.refresh(replica)
    
    logger.info(f"Created replica file record for {original_file.file_object_key} in {target_tier} tier")
    return replica
