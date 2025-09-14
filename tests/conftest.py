import os
import boto3


from botocore.exceptions import ClientError


class _DummyClient:
    def head_object(self, *args, **kwargs):
        error_response = {"Error": {"Code": "404", "Message": "Not Found"}}
        raise ClientError(error_response, "head_object")

    def generate_presigned_url(self, *args, **kwargs):
        return "url"

    def delete_object(self, *args, **kwargs):
        pass

    def create_multipart_upload(self, *args, **kwargs):
        return {"UploadId": "1"}

    def upload_part(self, *args, **kwargs):
        pass

    def complete_multipart_upload(self, *args, **kwargs):
        return {}

    def copy_object(self, *args, **kwargs):
        return {}


os.environ.setdefault("S3_BUCKET", "test-bucket")
boto3.client = lambda *args, **kwargs: _DummyClient()
