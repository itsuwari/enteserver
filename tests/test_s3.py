import importlib

import pytest
from fastapi.testclient import TestClient
from botocore.exceptions import ClientError
from unittest.mock import patch


class RecordingS3Client:
    def __init__(self, fail_first_part: bool = False):
        self.fail_first_part = fail_first_part
        self.upload_part_calls = 0
        self.multipart_uploads: list[tuple[str, str, str]] = []
        self.uploaded_parts: list[tuple[int, bytes]] = []
        self.put_calls: list[tuple[str, str, bytes]] = []
        self.aborted = 0
        self.completed_uploads = 0
        self.completed_parts: list[dict] | None = None

    def create_multipart_upload(self, Bucket, Key):
        upload_id = f"upload-{len(self.multipart_uploads) + 1}"
        self.multipart_uploads.append((Bucket, Key, upload_id))
        return {"UploadId": upload_id}

    def upload_part(self, Bucket, Key, UploadId, PartNumber, Body):
        self.upload_part_calls += 1
        if self.fail_first_part and self.upload_part_calls == 1:
            raise ClientError({"Error": {"Code": "RequestTimeout", "Message": "fail"}}, "UploadPart")
        chunk = bytes(Body)
        self.uploaded_parts.append((PartNumber, chunk))
        return {"ETag": f"etag-{PartNumber}"}

    def complete_multipart_upload(self, Bucket, Key, UploadId, MultipartUpload):
        self.completed_uploads += 1
        self.completed_parts = MultipartUpload["Parts"]
        return {}

    def abort_multipart_upload(self, Bucket, Key, UploadId):
        self.aborted += 1

    def put_object(self, Bucket, Key, Body):
        self.put_calls.append((Bucket, Key, bytes(Body)))
        return {}


@pytest.fixture
def s3_mod():
    import app.config as config
    import app.s3 as s3

    importlib.reload(config)
    importlib.reload(s3)

    class DummyClient:
        def head_object(self, Bucket, Key):
            error_response = {"Error": {"Code": "404", "Message": "Not Found"}}
            raise ClientError(error_response, "head_object")

        def generate_presigned_url(self, *args, **kwargs):
            return "url"

        def delete_object(self, Bucket, Key):
            pass

    return s3, DummyClient


def test_presign_get_raises_when_missing(s3_mod):
    s3, Dummy = s3_mod
    # use two tiers to ensure loop over multiple backends
    dummy1 = Dummy()
    dummy2 = Dummy()
    s3._multicloud_s3.clients = {"tier1": dummy1, "tier2": dummy2}
    s3._multicloud_s3.buckets = {"tier1": "bucket1", "tier2": "bucket2"}
    with pytest.raises(FileNotFoundError):
        s3.presign_get("foo", tier="tier1")


def test_delete_object_requires_tier_when_not_all(s3_mod):
    s3, _ = s3_mod
    with pytest.raises(ValueError):
        s3.delete_object("foo", all_tiers=False)


def test_multi_cloud_requires_backend_validation(s3_mod):
    s3, _ = s3_mod
    # remove configured bucket and backends to trigger validation
    s3.settings.s3_bucket = None
    s3.settings.s3_backends = {}
    with pytest.raises(ValueError):
        s3.MultiCloudS3()


def test_local_backend_roundtrip(tmp_path):
    import app.config as config
    import app.s3 as s3
    import app.main as main

    importlib.reload(config)
    try:
        with config.override(
            s3_backends={
                "main": {
                    "type": "local",
                    "base_path": str(tmp_path),
                    "base_url": "http://testserver",
                }
            }
        ):
            importlib.reload(s3)
            importlib.reload(main)

            client = TestClient(main.app)
            put_url = s3.presign_put("1/sample.bin")
            resp = client.put(put_url, data=b"hello world")
            assert resp.status_code == 200
            get_url = s3.presign_get("1/sample.bin")
            resp = client.get(get_url)
            assert resp.status_code == 200
            assert resp.content == b"hello world"
            assert "ETag" in resp.headers
    finally:
        importlib.reload(s3)
        importlib.reload(main)


def test_resolve_presigned_url_uses_request_host(tmp_path):
    import app.s3 as s3
    from app.local_s3 import LocalS3Client

    client = LocalS3Client(name="primary", base_path=str(tmp_path), secret="secret")
    raw_url = client.generate_presigned_url(
        "put_object",
        Params={"Bucket": None, "Key": "1/sample.bin"},
        ExpiresIn=60,
        HttpMethod="PUT",
    )

    resolved = s3.resolve_presigned_url(raw_url, "http://example.com/api")
    assert resolved.startswith("http://example.com/api/local-storage/primary/1/sample.bin")
    assert "expires=" in resolved and "signature=" in resolved


def test_chunked_remote_copy_retries(tmp_path):
    from app.local_s3 import LocalS3Client
    from app.s3 import MultiCloudS3

    local_client = LocalS3Client(name="local", base_path=str(tmp_path / "src"), secret="secret")
    data = b"abcdefghij"  # 10 bytes to trigger multiple chunks with chunk_size=4
    local_client.save_object("items/sample.bin", [data])

    target_client = RecordingS3Client(fail_first_part=True)

    with patch.object(MultiCloudS3, "_init_backends", lambda self: None):
        mc = MultiCloudS3()

    mc.clients = {"source": local_client, "target": target_client}
    mc.buckets = {"source": "ignored", "target": "bucket"}
    mc.backend_types = {"source": "local", "target": "s3"}
    mc.chunk_size = 4
    mc.max_copy_retries = 3
    mc.retry_backoff = 0

    assert mc.copy_object_between_buckets("items/sample.bin", "source", "target")
    assert target_client.put_calls == []
    assert len(target_client.multipart_uploads) == 2  # failure + retry
    assert target_client.aborted == 1
    assert target_client.completed_uploads == 1
    assert target_client.upload_part_calls == 4  # one failure, three successful parts
    assert target_client.uploaded_parts == [
        (1, b"abcd"),
        (2, b"efgh"),
        (3, b"ij"),
    ]
    assert target_client.completed_parts == [
        {"PartNumber": 1, "ETag": "etag-1"},
        {"PartNumber": 2, "ETag": "etag-2"},
        {"PartNumber": 3, "ETag": "etag-3"},
    ]


def test_chunked_remote_copy_small_object(tmp_path):
    from app.local_s3 import LocalS3Client
    from app.s3 import MultiCloudS3

    local_client = LocalS3Client(name="local", base_path=str(tmp_path / "src2"), secret="secret")
    local_client.save_object("items/tiny.bin", [b"hi"])

    target_client = RecordingS3Client()

    with patch.object(MultiCloudS3, "_init_backends", lambda self: None):
        mc = MultiCloudS3()

    mc.clients = {"source": local_client, "target": target_client}
    mc.buckets = {"source": "ignored", "target": "bucket"}
    mc.backend_types = {"source": "local", "target": "s3"}
    mc.chunk_size = 4
    mc.max_copy_retries = 2
    mc.retry_backoff = 0

    assert mc.copy_object_between_buckets("items/tiny.bin", "source", "target")
    assert target_client.multipart_uploads == []
    assert target_client.upload_part_calls == 0
    assert target_client.put_calls == [("bucket", "items/tiny.bin", b"hi")]
    assert target_client.completed_uploads == 0
