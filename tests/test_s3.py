import importlib
import pytest


@pytest.fixture
def s3_mod():
    import app.config as config
    import app.s3 as s3
    importlib.reload(config)
    importlib.reload(s3)

    class DummyClient:
        def head_object(self, Bucket, Key):
            raise Exception("missing")

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
