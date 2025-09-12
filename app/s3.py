
from __future__ import annotations
import boto3
import logging
import asyncio
import threading
from enum import Enum
from typing import Optional, Dict, Any, List
from botocore.client import Config as BotoConfig
from .config import settings

logger = logging.getLogger(__name__)

class StorageTier(Enum):
    PRIMARY = "primary"  # B2 EU Central - Hot storage
    SECONDARY = "secondary"  # Wasabi EU Central - Hot storage backup
    COLD = "cold"  # Scaleway EU France - Cold storage

class MultiCloudS3:
    """Multi-cloud S3 implementation for Ente Museum compatibility"""
    
    def __init__(self):
        self.clients = self._init_clients()
        self.buckets = {
            StorageTier.PRIMARY: settings.s3_b2_eu_cen_bucket,
            StorageTier.SECONDARY: settings.s3_wasabi_eu_central_bucket,
            StorageTier.COLD: settings.s3_scw_eu_fr_bucket,
        }
    
    def _init_clients(self) -> Dict[StorageTier, Any]:
        """Initialize S3 clients for different storage tiers"""
        clients = {}
        
        # Primary client (current single-cloud setup)
        clients[StorageTier.PRIMARY] = boto3.client(
            "s3",
            aws_access_key_id=settings.s3_access_key,
            aws_secret_access_key=settings.s3_secret_key,
            endpoint_url=settings.s3_endpoint_url,
            region_name=settings.s3_region,
            config=BotoConfig(
                signature_version="s3v4", 
                s3={"addressing_style": "path" if settings.s3_use_path_style else "virtual"}
            ),
        )
        
        # For now, use the same client for all tiers (can be extended)
        clients[StorageTier.SECONDARY] = clients[StorageTier.PRIMARY]
        clients[StorageTier.COLD] = clients[StorageTier.PRIMARY]
        
        return clients
    
    def get_client(self, tier: StorageTier = StorageTier.PRIMARY):
        """Get S3 client for specific storage tier"""
        return self.clients[tier]
    
    def get_bucket(self, tier: StorageTier = StorageTier.PRIMARY) -> str:
        """Get bucket name for specific storage tier"""
        return self.buckets.get(tier, settings.s3_bucket)
    
    def get_replication_targets(self, subscription_type: str, source_tier: StorageTier) -> List[StorageTier]:
        """Get target tiers for replication - all users get full replication"""
        targets = []
        
        # All users get full replication regardless of subscription
        if source_tier == StorageTier.PRIMARY:
            targets.extend([StorageTier.SECONDARY, StorageTier.COLD])
        elif source_tier == StorageTier.SECONDARY:
            targets.append(StorageTier.COLD)
        
        return targets
    
    def copy_object_between_buckets(self, key: str, source_tier: StorageTier, target_tier: StorageTier) -> bool:
        """Copy object from source tier to target tier"""
        try:
            source_bucket = self.get_bucket(source_tier)
            target_bucket = self.get_bucket(target_tier)
            source_client = self.get_client(source_tier)
            target_client = self.get_client(target_tier)
            
            # For now, if buckets are the same (single S3 setup), just log
            if source_bucket == target_bucket:
                logger.info(f"Simulated replication: {key} from {source_tier.value} to {target_tier.value}")
                return True
            
            # Copy object from source to target
            copy_source = {'Bucket': source_bucket, 'Key': key}
            target_client.copy_object(
                CopySource=copy_source,
                Bucket=target_bucket,
                Key=key
            )
            
            logger.info(f"Successfully replicated {key} from {source_tier.value} to {target_tier.value}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to replicate {key} from {source_tier.value} to {target_tier.value}: {e}")
            return False
    
    def replicate_to_tiers(self, key: str, subscription_type: str, source_tier: StorageTier = StorageTier.PRIMARY, original_file=None, db=None) -> Dict[str, bool]:
        """Replicate object to appropriate tiers based on subscription"""
        targets = self.get_replication_targets(subscription_type, source_tier)
        results = {}
        
        for target_tier in targets:
            success = self.copy_object_between_buckets(key, source_tier, target_tier)
            results[target_tier.value] = success
            
            # Create replica file record if replication succeeded and we have the original file
            if success and original_file and db:
                try:
                    from .storage import create_replica_file_record
                    create_replica_file_record(original_file, target_tier.value, db)
                    logger.info(f"Created replica record for {key} in {target_tier.value} tier")
                except Exception as e:
                    logger.error(f"Failed to create replica record for {key} in {target_tier.value}: {e}")
        
        return results
    
    def replicate_to_all_tiers(self, key: str, subscription_type: str = "free", source_tier: StorageTier = StorageTier.PRIMARY) -> bool:
        """Replicate object to all appropriate tiers based on subscription"""
        results = self.replicate_to_tiers(key, subscription_type, source_tier)
        
        if not results:
            logger.info(f"No replication targets for {subscription_type} subscription")
            return True
        
        success_count = sum(1 for success in results.values() if success)
        total_count = len(results)
        
        logger.info(f"Replication completed for {key}: {success_count}/{total_count} successful")
        return success_count == total_count

# Global multi-cloud S3 instance
_multicloud_s3 = MultiCloudS3()

def _client(tier: StorageTier = StorageTier.PRIMARY):
    """Get S3 client for specific tier (backward compatibility)"""
    return _multicloud_s3.get_client(tier)

def _bucket(tier: StorageTier = StorageTier.PRIMARY) -> str:
    """Get bucket name for specific tier"""
    return _multicloud_s3.get_bucket(tier)

def presign_put(key: str, content_type: str | None = None, expires: int | None = None, tier: StorageTier = StorageTier.PRIMARY) -> str:
    """Generate presigned PUT URL for uploading to specific storage tier"""
    params = {"Bucket": _bucket(tier), "Key": key}
    if content_type:
        params["ContentType"] = content_type
    return _client(tier).generate_presigned_url("put_object", Params=params, ExpiresIn=expires or settings.s3_presign_expiry, HttpMethod="PUT")

def presign_get(key: str, response_filename: str | None = None, expires: int | None = None, tier: StorageTier = StorageTier.PRIMARY) -> str:
    """Generate presigned GET URL with tier fallback for downloads"""
    # Try primary tier first, fallback to secondary if needed
    for fallback_tier in [tier, StorageTier.PRIMARY, StorageTier.SECONDARY]:
        try:
            params = {"Bucket": _bucket(fallback_tier), "Key": key}
            if response_filename:
                params["ResponseContentDisposition"] = f'attachment; filename="{response_filename}"'
            
            # Check if object exists in this tier
            try:
                _client(fallback_tier).head_object(Bucket=_bucket(fallback_tier), Key=key)
                return _client(fallback_tier).generate_presigned_url("get_object", Params=params, ExpiresIn=expires or settings.s3_presign_expiry, HttpMethod="GET")
            except Exception:
                continue
        except Exception:
            continue
    
    # Fallback to primary tier if all else fails
    params = {"Bucket": _bucket(StorageTier.PRIMARY), "Key": key}
    if response_filename:
        params["ResponseContentDisposition"] = f'attachment; filename="{response_filename}"'
    return _client(StorageTier.PRIMARY).generate_presigned_url("get_object", Params=params, ExpiresIn=expires or settings.s3_presign_expiry, HttpMethod="GET")

def mpu_init(key: str, tier: StorageTier = StorageTier.PRIMARY) -> str:
    """Initialize multipart upload on specific storage tier"""
    out = _client(tier).create_multipart_upload(Bucket=_bucket(tier), Key=key)
    return out["UploadId"]

def mpu_presign_part(key: str, upload_id: str, part_number: int, expires: int | None = None, tier: StorageTier = StorageTier.PRIMARY) -> str:
    """Generate presigned URL for multipart upload part"""
    return _client(tier).generate_presigned_url(
        "upload_part",
        Params={"Bucket": _bucket(tier), "Key": key, "UploadId": upload_id, "PartNumber": part_number},
        ExpiresIn=expires or settings.s3_presign_expiry,
        HttpMethod="PUT"
    )

def mpu_complete(key: str, upload_id: str, parts: list[dict], tier: StorageTier = StorageTier.PRIMARY, subscription_type: str = "free"):
    """Complete multipart upload and trigger replication"""
    result = _client(tier).complete_multipart_upload(
        Bucket=_bucket(tier),
        Key=key,
        UploadId=upload_id,
        MultipartUpload={"Parts": parts}
    )
    
    # Automatically replicate to appropriate tiers based on subscription
    _multicloud_s3.replicate_to_all_tiers(key, subscription_type, tier)
    
    return result

def delete_object(key: str, all_tiers: bool = True) -> bool:
    """Delete object from one or all storage tiers"""
    success = True
    
    if all_tiers:
        # Delete from all tiers
        for tier in StorageTier:
            try:
                _client(tier).delete_object(Bucket=_bucket(tier), Key=key)
                logger.info(f"Deleted {key} from {tier.value} tier")
            except Exception as e:
                logger.warning(f"Failed to delete {key} from {tier.value} tier: {e}")
                success = False
    else:
        # Delete from primary tier only
        try:
            _client(StorageTier.PRIMARY).delete_object(Bucket=_bucket(StorageTier.PRIMARY), Key=key)
        except Exception:
            success = False
    
    return success

def get_object_info(key: str, tier: StorageTier = StorageTier.PRIMARY) -> Optional[Dict[str, Any]]:
    """Get object metadata from specific storage tier"""
    try:
        response = _client(tier).head_object(Bucket=_bucket(tier), Key=key)
        return {
            "size": response.get("ContentLength"),
            "etag": response.get("ETag", "").strip('"'),
            "last_modified": response.get("LastModified"),
            "content_type": response.get("ContentType"),
        }
    except Exception:
        return None

def replicate_object(key: str, source_tier: StorageTier, target_tier: StorageTier) -> bool:
    """Replicate object between storage tiers"""
    return _multicloud_s3.copy_object_between_buckets(key, source_tier, target_tier)

def replicate_after_upload(key: str, subscription_type: str, tier: StorageTier = StorageTier.PRIMARY, original_file=None, db=None) -> Dict[str, bool]:
    """Automatically replicate object after upload based on subscription"""
    return _multicloud_s3.replicate_to_tiers(key, subscription_type, tier, original_file, db)

def get_available_tiers_for_subscription(subscription_type: str) -> List[StorageTier]:
    """Get list of available storage tiers - all users get all tiers"""
    # All users get access to all storage tiers regardless of subscription
    return [StorageTier.PRIMARY, StorageTier.SECONDARY, StorageTier.COLD]

# Backward compatibility functions
def head_object_size_and_etag(key: str) -> tuple[Optional[int], Optional[str]]:
    """Get object size and etag with tier fallback"""
    for tier in StorageTier:
        info = get_object_info(key, tier)
        if info:
            return info["size"], info["etag"]
    return None, None
