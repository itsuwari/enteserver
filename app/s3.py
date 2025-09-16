from __future__ import annotations

import boto3
import logging
import time
from contextlib import closing, suppress
from typing import Optional, Dict, Any, List
from urllib.parse import urljoin
from botocore.client import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy.exc import SQLAlchemyError

from .config import settings
from .local_s3 import LocalS3Client, LocalS3Error

logger = logging.getLogger(__name__)

class MultiCloudS3:
    """Dynamic multi-backend S3 implementation"""

    def __init__(self):
        self.clients: Dict[str, Any] = {}
        self.buckets: Dict[str, str] = {}
        self.backend_types: Dict[str, str] = {}
        self.chunk_size = 5 * 1024 * 1024
        self.max_copy_retries = 3
        self.retry_backoff = 0.5
        self._init_backends()

    def _init_backends(self) -> None:
        backends = settings.s3_backends or {}
        if backends:
            for name, cfg in backends.items():
                backend_type = (cfg.get("type") or "s3").lower()
                if backend_type == "local":
                    base_path = cfg.get("base_path")
                    if not base_path:
                        raise ValueError(f"Local backend '{name}' requires 'base_path'")
                    base_url = cfg.get("base_url") or cfg.get("url")
                    secret = cfg.get("secret") or settings.jwt_secret
                    client = LocalS3Client(name=name, base_path=base_path, base_url=base_url, secret=secret)
                    bucket = cfg.get("bucket") or name
                else:
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
                self.backend_types[name] = backend_type
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
            self.backend_types["main"] = "s3"

    def get_client(self, tier: str = "main"):
        return self.clients[tier]

    def get_bucket(self, tier: str = "main") -> str:
        return self.buckets[tier]

    def get_backend_type(self, tier: str) -> str:
        return self.backend_types.get(tier, "s3")

    def get_replication_targets(self, subscription_type: str, source_tier: str) -> List[str]:
        return [t for t in self.clients.keys() if t != source_tier]

    def copy_object_between_buckets(self, key: str, source_tier: str, target_tier: str) -> bool:
        attempts = 0
        while attempts < self.max_copy_retries:
            attempts += 1
            try:
                self._copy_object_once(key, source_tier, target_tier)
                logger.info(
                    f"Successfully replicated {key} from {source_tier} to {target_tier} (attempt {attempts})"
                )
                return True
            except (
                BotoCoreError,
                ClientError,
                LocalS3Error,
                FileNotFoundError,
                OSError,
                AttributeError,
            ) as e:
                logger.error(
                    f"Attempt {attempts} failed to replicate {key} from {source_tier} to {target_tier}: {e}"
                )
                if attempts >= self.max_copy_retries:
                    break
                backoff = self.retry_backoff * (2 ** (attempts - 1))
                if backoff > 0:
                    time.sleep(backoff)
        logger.error(
            f"Failed to replicate {key} from {source_tier} to {target_tier} after {self.max_copy_retries} attempts"
        )
        return False

    def _copy_object_once(self, key: str, source_tier: str, target_tier: str) -> None:
        source_client = self.get_client(source_tier)
        target_client = self.get_client(target_tier)
        source_type = self.get_backend_type(source_tier)
        target_type = self.get_backend_type(target_tier)

        if source_type == "local":
            if target_type == "local":
                if source_client.base_path == target_client.base_path:
                    logger.info(
                        f"Simulated replication: {key} within {source_tier} (same storage root)"
                    )
                    return
                source_path = source_client.get_existing_path(key)
                target_client.copy_from_path(key, source_path)
                return

            target_bucket = self.get_bucket(target_tier)
            with source_client.open_for_read(key) as fh:
                self._upload_stream_to_s3(target_client, target_bucket, key, fh)
            return

        source_bucket = self.get_bucket(source_tier)

        if target_type == "local":
            with target_client.open_for_write(key) as dest:
                self._download_s3_to_stream(source_client, source_bucket, key, dest)
            return

        target_bucket = self.get_bucket(target_tier)
        if source_type == "s3" and target_type == "s3" and source_bucket == target_bucket:
            logger.info(f"Simulated replication: {key} from {source_tier} to {target_tier}")
            return

        response = source_client.get_object(Bucket=source_bucket, Key=key)
        with closing(response["Body"]) as body:
            self._upload_stream_to_s3(target_client, target_bucket, key, body)

    def _read_chunk(self, stream) -> bytes:
        chunk = stream.read(self.chunk_size)
        if not chunk:
            return b""
        if isinstance(chunk, bytes):
            return chunk
        return bytes(chunk)

    def _iter_additional_chunks(self, stream):
        while True:
            chunk = self._read_chunk(stream)
            if not chunk:
                break
            yield chunk

    def _upload_stream_to_s3(self, client, bucket: str, key: str, stream) -> None:
        first_chunk = self._read_chunk(stream)
        if not first_chunk:
            client.put_object(Bucket=bucket, Key=key, Body=b"")
            return

        second_chunk = self._read_chunk(stream)
        if not second_chunk:
            client.put_object(Bucket=bucket, Key=key, Body=first_chunk)
            return

        upload = client.create_multipart_upload(Bucket=bucket, Key=key)
        upload_id = upload["UploadId"]
        parts: List[Dict[str, Any]] = []
        part_number = 1

        def _chunk_iterator():
            yield first_chunk
            yield second_chunk
            yield from self._iter_additional_chunks(stream)

        try:
            for chunk in _chunk_iterator():
                response = client.upload_part(
                    Bucket=bucket,
                    Key=key,
                    UploadId=upload_id,
                    PartNumber=part_number,
                    Body=chunk,
                )
                parts.append({"PartNumber": part_number, "ETag": response["ETag"]})
                part_number += 1
            client.complete_multipart_upload(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
        except Exception:
            if hasattr(client, "abort_multipart_upload"):
                with suppress(Exception):
                    client.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
            raise

    def _download_s3_to_stream(self, client, bucket: str, key: str, dest_stream) -> None:
        if hasattr(client, "download_fileobj"):
            client.download_fileobj(Bucket=bucket, Key=key, Fileobj=dest_stream)
            return

        response = client.get_object(Bucket=bucket, Key=key)
        with closing(response["Body"]) as body:
            for chunk in self._iter_additional_chunks(body):
                dest_stream.write(chunk)

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
                except SQLAlchemyError as e:
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
        except (BotoCoreError, ClientError, LocalS3Error, FileNotFoundError) as e:
            if isinstance(e, ClientError):
                if e.response.get("Error", {}).get("Code") not in ("404", "NoSuchKey"):
                    logger.warning(f"Error checking object '{key}' in tier '{fallback_tier}': {e}")
            elif not isinstance(e, FileNotFoundError):
                logger.warning(f"Error checking object '{key}' in tier '{fallback_tier}': {e}")
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
            except (BotoCoreError, ClientError, LocalS3Error, FileNotFoundError) as e:
                logger.warning(f"Failed to delete {key} from {t} tier: {e}")
                success = False
    else:
        if tier is None:
            raise ValueError("'tier' must be specified when all_tiers is False")
        try:
            _client(tier).delete_object(Bucket=_bucket(tier), Key=key)
        except (BotoCoreError, ClientError, LocalS3Error, FileNotFoundError) as e:
            logger.warning(f"Failed to delete {key} from {tier} tier: {e}")
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
    except (BotoCoreError, ClientError, LocalS3Error, FileNotFoundError):
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


def object_storage_available() -> bool:
    if has_local_backend():
        return True
    return settings.s3_enabled and bool(_multicloud_s3.clients)


def has_local_backend() -> bool:
    return any(isinstance(client, LocalS3Client) for client in _multicloud_s3.clients.values())


def get_local_client(tier: str) -> LocalS3Client | None:
    client = _multicloud_s3.clients.get(tier)
    if isinstance(client, LocalS3Client):
        return client
    return None


def resolve_presigned_url(url: str, base_url: str | None) -> str:
    """Ensure that presigned URLs are absolute when routed via FastAPI.

    Local backends emit relative URLs (``/local-storage/...``) so that they can
    be reverse proxied behind the API server.  Frontend clients, however, expect
    absolute URLs.  When a ``base_url`` is provided (typically derived from the
    incoming request), upgrade the relative URL to an absolute one that reuses
    the same host/port as the API.  Remote S3 URLs are already absolute and are
    returned as-is.
    """

    if url.startswith("http://") or url.startswith("https://"):
        return url
    if not base_url:
        return url

    normalized_base = base_url if base_url.endswith("/") else base_url + "/"
    # ``urljoin`` correctly handles query strings and relative paths.
    return urljoin(normalized_base, url.lstrip("/"))
