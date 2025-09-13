from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import User
from ..schemas import StorageUsageResponse, StorageQuotaUpdate, StorageBonusAdd
from ..security import get_current_user
from ..storage import (
    get_user_storage_usage, update_user_storage_usage, 
    set_user_storage_quota, add_storage_bonus, format_storage_size,
    get_tier_quota_for_user, get_user_replica_usage
)
from ..s3 import get_available_tiers_for_subscription

router = APIRouter(prefix="/storage", tags=["storage"])

@router.get("/usage", response_model=StorageUsageResponse)
def get_storage_usage(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get current user's storage usage and quota information"""
    usage_info = get_user_storage_usage(current_user.id, db)
    
    if "error" in usage_info:
        raise HTTPException(status_code=404, detail=usage_info["error"])
    
    return StorageUsageResponse(
        used=usage_info["used"],
        quota=usage_info["quota"],
        bonus=usage_info["bonus"],
        total_quota=usage_info["total_quota"],
        available=usage_info["available"],
        usage_percentage=usage_info["usage_percentage"],
        formatted_used=format_storage_size(usage_info["used"]),
        formatted_quota=format_storage_size(usage_info["total_quota"]),
        formatted_available=format_storage_size(usage_info["available"])
    )

@router.post("/refresh")
def refresh_storage_usage(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Recalculate and update user's storage usage from actual files"""
    usage_info = update_user_storage_usage(current_user.id, db)
    
    if "error" in usage_info:
        raise HTTPException(status_code=404, detail=usage_info["error"])
    
    return {
        "message": "Storage usage updated",
        "used": usage_info["used"],
        "formatted_used": format_storage_size(usage_info["used"])
    }

@router.get("/tier-quotas")
def get_tier_quotas(current_user: User = Depends(get_current_user)):
    """Get storage tier quotas based on user's subscription"""
    tier_quotas = get_tier_quota_for_user(current_user)
    
    return {
        "subscription_type": current_user.subscription_type,
        "quotas": {
            "total": {
                "bytes": tier_quotas["total"],
                "formatted": format_storage_size(tier_quotas["total"])
            },
            "primary": {
                "bytes": tier_quotas["primary"],
                "formatted": format_storage_size(tier_quotas["primary"])
            },
            "secondary": {
                "bytes": tier_quotas["secondary"],
                "formatted": format_storage_size(tier_quotas["secondary"])
            },
            "cold": {
                "bytes": tier_quotas["cold"],
                "formatted": format_storage_size(tier_quotas["cold"])
            }
        }
    }

@router.get("/replication-info")
def get_replication_info(current_user: User = Depends(get_current_user)):
    """Get replication information and available tiers for user"""
    available_tiers = get_available_tiers_for_subscription(current_user.subscription_type)

    return {
        "subscription_type": current_user.subscription_type,
        "available_tiers": available_tiers,
        "automatic_replication": True,
    }

@router.get("/detailed-usage")
def get_detailed_storage_usage(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get detailed storage usage breakdown by tier including replicas"""
    replica_usage = get_user_replica_usage(current_user.id, db)
    regular_usage = get_user_storage_usage(current_user.id, db)
    
    return {
        "user_id": current_user.id,
        "subscription_type": current_user.subscription_type,
        "quota_usage": {
            "used": replica_usage["quota_usage"],
            "quota": regular_usage["quota"],
            "bonus": regular_usage["bonus"],
            "total_quota": regular_usage["total_quota"],
            "available": regular_usage["available"],
            "usage_percentage": regular_usage["usage_percentage"],
            "formatted_used": format_storage_size(replica_usage["quota_usage"]),
            "formatted_quota": format_storage_size(regular_usage["total_quota"]),
            "formatted_available": format_storage_size(regular_usage["available"])
        },
        "tier_breakdown": {
            "primary": {
                "usage": replica_usage["primary_usage"],
                "formatted": format_storage_size(replica_usage["primary_usage"]),
                "counts_against_quota": True
            },
            "secondary": {
                "usage": replica_usage["secondary_usage"],
                "formatted": format_storage_size(replica_usage["secondary_usage"]),
                "counts_against_quota": False
            },
            "cold": {
                "usage": replica_usage["cold_usage"],
                "formatted": format_storage_size(replica_usage["cold_usage"]),
                "counts_against_quota": False
            }
        },
        "replication_summary": {
            "total_replicated": replica_usage["total_replicated"],
            "formatted_replicated": format_storage_size(replica_usage["total_replicated"]),
            "replication_ratio": (replica_usage["total_replicated"] / replica_usage["primary_usage"]) if replica_usage["primary_usage"] > 0 else 0
        }
    }

# Admin endpoints (would need admin authentication in production)
@router.put("/admin/quota/{user_id}")
def admin_set_user_quota(user_id: int, payload: StorageQuotaUpdate, db: Session = Depends(get_db)):
    """Admin: Set storage quota for a specific user"""
    # TODO: Add admin authentication check
    success = set_user_storage_quota(user_id, payload.new_quota, db)
    
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "message": f"Storage quota updated for user {user_id}",
        "new_quota": payload.new_quota,
        "formatted_quota": format_storage_size(payload.new_quota)
    }

@router.post("/admin/bonus/{user_id}")
def admin_add_storage_bonus(user_id: int, payload: StorageBonusAdd, db: Session = Depends(get_db)):
    """Admin: Add bonus storage to a specific user"""
    # TODO: Add admin authentication check
    success = add_storage_bonus(user_id, payload.bonus_bytes, db)
    
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "message": f"Added {format_storage_size(payload.bonus_bytes)} bonus storage to user {user_id}",
        "bonus_bytes": payload.bonus_bytes,
        "reason": payload.reason
    }

@router.get("/admin/usage/{user_id}")
def admin_get_user_storage_usage(user_id: int, db: Session = Depends(get_db)):
    """Admin: Get storage usage for any user"""
    # TODO: Add admin authentication check
    usage_info = get_user_storage_usage(user_id, db)
    
    if "error" in usage_info:
        raise HTTPException(status_code=404, detail=usage_info["error"])
    
    return {
        "user_id": user_id,
        "usage": usage_info,
        "formatted": {
            "used": format_storage_size(usage_info["used"]),
            "quota": format_storage_size(usage_info["total_quota"]),
            "available": format_storage_size(usage_info["available"])
        }
    }