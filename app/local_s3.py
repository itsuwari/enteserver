from __future__ import annotations

import hashlib
import hmac
import json
import mimetypes
import shutil
import time
import uuid
from pathlib import Path
from typing import AsyncIterator, Dict, Iterable, Optional

from botocore.exceptions import ClientError


class LocalS3Error(RuntimeError):
    """Internal error raised for invalid local S3 operations."""


class LocalS3Client:
    """Minimal S3-compatible interface backed by the local filesystem."""

    def __init__(
        self,
        name: str,
        base_path: str,
        *,
        base_url: str | None = None,
        secret: str,
    ) -> None:
        self.name = name
        self.base_path = Path(base_path).expanduser().resolve()
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.base_url = base_url.rstrip("/") if base_url else ""
        self._secret = secret.encode("utf-8")
        self._multipart_dir = self.base_path / ".multipart"
        self._multipart_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _normalize_key(self, key: str) -> str:
        return key.lstrip("/")

    def _object_path(self, key: str, *, create_parents: bool = True) -> Path:
        normalized = self._normalize_key(key)
        path = (self.base_path / normalized).resolve()
        if not str(path).startswith(str(self.base_path)):
            raise LocalS3Error("Attempted path traversal outside storage root")
        if create_parents:
            path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _existing_object_path(self, key: str) -> Path:
        path = self._object_path(key, create_parents=False)
        if not path.exists():
            error_response = {"Error": {"Code": "404", "Message": "Not Found"}}
            raise ClientError(error_response, "HeadObject")
        return path

    def _multipart_path(self, upload_id: str) -> Path:
        upload_dir = (self._multipart_dir / upload_id).resolve()
        if not str(upload_dir).startswith(str(self._multipart_dir)):
            raise LocalS3Error("Invalid multipart upload identifier")
        upload_dir.mkdir(parents=True, exist_ok=True)
        return upload_dir

    def _multipart_meta_path(self, upload_id: str) -> Path:
        return self._multipart_path(upload_id) / "meta.json"

    def _sign(self, method: str, key: str, expires: int, extra: Optional[Dict[str, str]] = None) -> str:
        normalized_key = self._normalize_key(key)
        components = [method.upper(), self.name, normalized_key, str(expires)]
        if extra:
            for k in sorted(extra):
                components.append(f"{k}={extra[k]}")
        message = "\n".join(components).encode("utf-8")
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()

    def verify_signature(
        self,
        method: str,
        key: str,
        expires: int,
        signature: str,
        extra: Optional[Dict[str, str]] = None,
    ) -> None:
        if expires < int(time.time()):
            raise LocalS3Error("URL expired")
        expected = self._sign(method, key, expires, extra)
        if not hmac.compare_digest(expected, signature):
            raise LocalS3Error("Invalid signature")

    # ------------------------------------------------------------------
    # HTTP URL helpers
    # ------------------------------------------------------------------
    def _build_url(self, key: str, expires: int, params: Dict[str, str]) -> str:
        from urllib.parse import urlencode, quote

        encoded_key = quote(self._normalize_key(key), safe="/")
        query = urlencode(params, quote_via=quote)
        prefix = self.base_url or ""
        return f"{prefix}/local-storage/{self.name}/{encoded_key}?{query}"

    def generate_presigned_url(
        self,
        operation_name: str,
        *,
        Params: Dict[str, object],
        ExpiresIn: int,
        HttpMethod: str,
    ) -> str:
        key_value = Params.get("Key") if Params else None
        key = str(key_value) if key_value is not None else f"{self.name}/health"
        expires = int(time.time()) + int(ExpiresIn)
        extra: Dict[str, str] = {}

        if operation_name == "upload_part":
            extra["uploadId"] = str(Params["UploadId"])
            extra["partNumber"] = str(Params["PartNumber"])
        elif operation_name == "get_object":
            if "ResponseContentDisposition" in Params:
                extra["response-content-disposition"] = str(Params["ResponseContentDisposition"])
        params = dict(extra)
        params["expires"] = str(expires)
        params["signature"] = self._sign(HttpMethod, key, expires, extra)
        return self._build_url(key, expires, params)

    # ------------------------------------------------------------------
    # Multipart upload helpers
    # ------------------------------------------------------------------
    def create_multipart_upload(self, *, Bucket: str | None, Key: str) -> Dict[str, str]:
        upload_id = uuid.uuid4().hex
        meta = {"Key": Key}
        meta_path = self._multipart_meta_path(upload_id)
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        meta_path.write_text(json.dumps(meta))
        return {"UploadId": upload_id}

    def _load_multipart_meta(self, upload_id: str) -> Dict[str, object]:
        meta_path = self._multipart_meta_path(upload_id)
        if not meta_path.exists():
            raise LocalS3Error("Unknown multipart upload")
        return json.loads(meta_path.read_text())

    def store_multipart_part(self, upload_id: str, part_number: int, data: Iterable[bytes]) -> str:
        self._load_multipart_meta(upload_id)
        upload_dir = self._multipart_path(upload_id)
        part_path = upload_dir / f"part_{part_number:05d}"
        md5 = hashlib.md5()
        with part_path.open("wb") as fh:
            for chunk in data:
                fh.write(chunk)
                md5.update(chunk)
        return md5.hexdigest()

    async def store_multipart_part_async(self, upload_id: str, part_number: int, data: AsyncIterator[bytes]) -> str:
        self._load_multipart_meta(upload_id)
        upload_dir = self._multipart_path(upload_id)
        part_path = upload_dir / f"part_{part_number:05d}"
        md5 = hashlib.md5()
        with part_path.open("wb") as fh:
            async for chunk in data:
                fh.write(chunk)
                md5.update(chunk)
        return md5.hexdigest()

    def complete_multipart_upload(self, *, Bucket: str | None, Key: str, UploadId: str, MultipartUpload: Dict[str, object]):
        self._load_multipart_meta(UploadId)
        upload_dir = self._multipart_path(UploadId)
        parts = MultipartUpload.get("Parts") or []
        dest_path = self._object_path(Key)
        md5 = hashlib.md5()
        with dest_path.open("wb") as dest:
            for part in sorted(parts, key=lambda p: p["PartNumber"]):
                part_path = upload_dir / f"part_{part['PartNumber']:05d}"
                if not part_path.exists():
                    raise LocalS3Error(f"Missing part {part['PartNumber']}")
                with part_path.open("rb") as src:
                    while True:
                        chunk = src.read(1024 * 1024)
                        if not chunk:
                            break
                        dest.write(chunk)
                        md5.update(chunk)
        shutil.rmtree(upload_dir, ignore_errors=True)
        return {"ETag": md5.hexdigest()}

    # ------------------------------------------------------------------
    # Object helpers for HTTP handlers and replication
    # ------------------------------------------------------------------
    def save_object(self, key: str, data: Iterable[bytes]) -> str:
        path = self._object_path(key)
        md5 = hashlib.md5()
        with path.open("wb") as fh:
            for chunk in data:
                fh.write(chunk)
                md5.update(chunk)
        return md5.hexdigest()

    async def save_object_async(self, key: str, data: AsyncIterator[bytes]) -> str:
        path = self._object_path(key)
        md5 = hashlib.md5()
        with path.open("wb") as fh:
            async for chunk in data:
                fh.write(chunk)
                md5.update(chunk)
        return md5.hexdigest()

    def open_for_read(self, key: str):
        path = self._existing_object_path(key)
        return path.open("rb")

    def write_fileobj(self, key: str, fileobj) -> None:
        path = self._object_path(key)
        with path.open("wb") as dest:
            shutil.copyfileobj(fileobj, dest)

    def open_for_write(self, key: str):
        path = self._object_path(key)
        return path.open("wb")

    def copy_from_path(self, key: str, source_path: Path) -> None:
        dest_path = self._object_path(key)
        shutil.copy2(source_path, dest_path)

    def head_object(self, *, Bucket: str | None, Key: str) -> Dict[str, object]:
        try:
            path = self._existing_object_path(Key)
        except ClientError as exc:
            raise exc
        stat = path.stat()
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        etag = self._compute_etag(path)
        return {
            "ContentLength": stat.st_size,
            "ETag": etag,
            "LastModified": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(stat.st_mtime)),
            "ContentType": content_type,
        }

    def delete_object(self, *, Bucket: str | None, Key: str) -> None:
        path = self._object_path(Key, create_parents=False)
        if path.exists():
            path.unlink()

    def _compute_etag(self, path: Path) -> str:
        md5 = hashlib.md5()
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                md5.update(chunk)
        return md5.hexdigest()

    def get_existing_path(self, key: str) -> Path:
        return self._existing_object_path(key)

