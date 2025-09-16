import importlib

import pytest
from fastapi.testclient import TestClient
from botocore.exceptions import ClientError


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
