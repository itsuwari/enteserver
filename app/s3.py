from __future__ import annotations
import boto3
import logging
from typing import Optional, Dict, Any, List
from botocore.client import Config as BotoConfig
from .config import settings

logger = logging.getLogger(__name__)

class MultiCloudS3:
    """Dynamic multi-backend S3 implementation"""

    def __init__(self):
        self.clients: Dict[str, Any] = {}
        self.buckets: Dict[str, str] = {}
        self._init_backends()

    def _init_backends(self) -> None:
        backends = settings.s3_backends or {}
        if backends:
            for name, cfg in backends.items():
                bucket = cfg.get("bucket", settings.s3_bucket)
                if not bucket:
                    raise ValueError(f"No bucket configured for backend '{name}'")
                client = boto3.client(
                    "s3",
                    aws_access_key_id=cfg.get("access_key", settings.s3_access_key),
                    aws_secret_access_key=cfg.get("secret_key", settings.s3_secret_key),
                    endpoint_url=cfg.get("endpoint_url", settings.s3_endpoint_url),
                    region_name=cfg.get("region", settings.s3_region),
                    config=BotoConfig(
                        signature_version="s3v4",
                        s3={"addressing_style": "path" if settings.s3_use_path_style else "virtual"},
                    ),
                )
                self.clients[name] = client
                self.buckets[name] = bucket
        else:
            if not settings.s3_bucket:
                raise ValueError("No S3 backend configured. Set 's3_bucket' or define 's3_backends'.")
            client = boto3.client(
                "s3",
                aws_access_key_id=settings.s3_access_key,
                aws_secret_access_key=settings.s3_secret_key,
                endpoint_url=settings.s3_endpoint_url,
                region_name=settings.s3_region,
                config=BotoConfig(
                    signature_version="s3v4",
                    s3={"addressing_style": "path" if settings.s3_use_path_style else "virtual"},
                ),
            )
            self.clients["main"] = client
            self.buckets["main"] = settings.s3_bucket

    def get_client(self, tier: str = "main"):
        return self.clients[tier]

    def get_bucket(self, tier: str = "main") -> str:
        return self.buckets[tier]

    def get_replication_targets(self, subscription_type: str, source_tier: str) -> List[str]:
        return [t for t in self.clients.keys() if t != source_tier]

    def copy_object_between_buckets(self, key: str, source_tier: str, target_tier: str) -> bool:
        try:
            source_bucket = self.get_bucket(source_tier)
            target_bucket = self.get_bucket(target_tier)
            source_client = self.get_client(source_tier)
            target_client = self.get_client(target_tier)

            if source_bucket == target_bucket:
                logger.info(f"Simulated replication: {key} from {source_tier} to {target_tier}")
                return True

            copy_source = {"Bucket": source_bucket, "Key": key}
            target_client.copy_object(CopySource=copy_source, Bucket=target_bucket, Key=key)

            logger.info(f"Successfully replicated {key} from {source_tier} to {target_tier}")
            return True
        except Exception as e:
            logger.error(f"Failed to replicate {key} from {source_tier} to {target_tier}: {e}")
            return False

    def replicate_to_tiers(self, key: str, subscription_type: str, source_tier: str = "main", original_file=None, db=None) -> Dict[str, bool]:
        targets = self.get_replication_targets(subscription_type, source_tier)
        results: Dict[str, bool] = {}

        for target_tier in targets:
            success = self.copy_object_between_buckets(key, source_tier, target_tier)
            results[target_tier] = success

            if success and original_file and db:
                try:
                    from .storage import create_replica_file_record
                    create_replica_file_record(original_file, target_tier, db)
                    logger.info(f"Created replica record for {key} in {target_tier} tier")
                except Exception as e:
                    logger.error(f"Failed to create replica record for {key} in {target_tier}: {e}")

        return results

    def replicate_to_all_tiers(self, key: str, subscription_type: str = "free", source_tier: str = "main") -> bool:
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

def _client(tier: str = "main"):
    """Get S3 client for specific tier"""
    return _multicloud_s3.get_client(tier)

def _bucket(tier: str = "main") -> str:
    """Get bucket name for specific tier"""
    return _multicloud_s3.get_bucket(tier)

def presign_put(key: str, content_type: str | None = None, expires: int | None = None, tier: str = "main") -> str:
    params = {"Bucket": _bucket(tier), "Key": key}
    if content_type:
        params["ContentType"] = content_type
    return _client(tier).generate_presigned_url("put_object", Params=params, ExpiresIn=expires or settings.s3_presign_expiry, HttpMethod="PUT")

def presign_get(key: str, response_filename: str | None = None, expires: int | None = None, tier: str = "main") -> str:
    tiers = [tier] + [t for t in _multicloud_s3.clients.keys() if t != tier]
    for fallback_tier in tiers:
        try:
            params = {"Bucket": _bucket(fallback_tier), "Key": key}
            if response_filename:
                params["ResponseContentDisposition"] = f'attachment; filename="{response_filename}"'
            _client(fallback_tier).head_object(Bucket=_bucket(fallback_tier), Key=key)
            return _client(fallback_tier).generate_presigned_url(
                "get_object",
                Params=params,
                ExpiresIn=expires or settings.s3_presign_expiry,
                HttpMethod="GET",
            )
        except Exception:
            continue
    raise FileNotFoundError(f"Object '{key}' not found in any configured tier")

def mpu_init(key: str, tier: str = "main") -> str:
    out = _client(tier).create_multipart_upload(Bucket=_bucket(tier), Key=key)
    return out["UploadId"]

def mpu_presign_part(key: str, upload_id: str, part_number: int, expires: int | None = None, tier: str = "main") -> str:
    return _client(tier).generate_presigned_url(
        "upload_part",
        Params={"Bucket": _bucket(tier), "Key": key, "UploadId": upload_id, "PartNumber": part_number},
        ExpiresIn=expires or settings.s3_presign_expiry,
        HttpMethod="PUT",
    )

def mpu_complete(key: str, upload_id: str, parts: list[dict], tier: str = "main", subscription_type: str = "free"):
    result = _client(tier).complete_multipart_upload(
        Bucket=_bucket(tier),
        Key=key,
        UploadId=upload_id,
        MultipartUpload={"Parts": parts},
    )
    _multicloud_s3.replicate_to_all_tiers(key, subscription_type, tier)
    return result

def delete_object(key: str, tier: str | None = None, all_tiers: bool = True) -> bool:
    success = True
    if all_tiers:
        for t in list(_multicloud_s3.clients.keys()):
            try:
                _client(t).delete_object(Bucket=_bucket(t), Key=key)
                logger.info(f"Deleted {key} from {t} tier")
            except Exception as e:
                logger.warning(f"Failed to delete {key} from {t} tier: {e}")
                success = False
    else:
        if tier is None:
            raise ValueError("'tier' must be specified when all_tiers is False")
        try:
            _client(tier).delete_object(Bucket=_bucket(tier), Key=key)
        except Exception:
            success = False
    return success

def get_object_info(key: str, tier: str = "main") -> Optional[Dict[str, Any]]:
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

def replicate_object(key: str, source_tier: str, target_tier: str) -> bool:
    return _multicloud_s3.copy_object_between_buckets(key, source_tier, target_tier)

def replicate_after_upload(key: str, subscription_type: str, tier: str = "main", original_file=None, db=None) -> Dict[str, bool]:
    return _multicloud_s3.replicate_to_tiers(key, subscription_type, tier, original_file, db)

def get_available_tiers_for_subscription(subscription_type: str) -> List[str]:
    return list(_multicloud_s3.clients.keys())

def head_object_size_and_etag(key: str) -> tuple[Optional[int], Optional[str]]:
    for tier in _multicloud_s3.clients.keys():
        info = get_object_info(key, tier)
        if info:
            return info["size"], info["etag"]
    return None, None
