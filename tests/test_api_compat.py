from app.main import app
from fastapi.testclient import TestClient

expected_paths = {
    "/albums/collection/{token}": {"get"},
    "/albums/file/{token}": {"get"},
    "/collections": {"get", "post"},
    "/collections/v2": {"get"},
    "/files": {"post"},
    "/files/count": {"get"},
    "/files/data/preview-upload-url": {"get"},
    "/files/delete": {"post"},
    "/files/download/{file_id}": {"get"},
    "/files/duplicates": {"get"},
    "/files/info": {"post"},
    "/files/magic-metadata": {"put"},
    "/files/multipart-complete": {"post"},
    "/files/multipart-upload-urls": {"get"},
    "/files/preview/{file_id}": {"get"},
    "/files/restore": {"post"},
    "/files/size": {"post"},
    "/files/thumbnail": {"put"},
    "/files/trash": {"post"},
    "/files/update": {"put"},
    "/files/upload-urls": {"get"},
    "/healthz": {"get"},
    "/kex/add": {"put"},
    "/kex/get": {"get"},
    "/ping": {"get"},
    "/public/collections": {"post"},
    "/public/collections/{token}": {"get"},
    "/public/collections/{token}/commit-file": {"post"},
    "/public/collections/{token}/preview/{file_id}": {"get"},
    "/public/files/{token}": {"get"},
    "/storage/admin/bonus/{user_id}": {"post"},
    "/storage/admin/quota/{user_id}": {"put"},
    "/storage/admin/usage/{user_id}": {"get"},
    "/storage/detailed-usage": {"get"},
    "/storage/refresh": {"post"},
    "/storage/replication-info": {"get"},
    "/storage/tier-quotas": {"get"},
    "/storage/usage": {"get"},
    "/trash/delete": {"post"},
    "/trash/empty": {"post"},
    "/trash/v2/diff": {"get"},
    "/users/accounts-token": {"get"},
    "/users/login": {"post"},
    "/users/sessions": {"get"},
    "/users/sessions/current": {"delete"},
    "/users/sessions/revoke-others": {"post"},
    "/users/sessions/{session_id}": {"delete"},
    "/version": {"get"},
}

def test_api_paths_match_backend_spec():
    client = TestClient(app)
    openapi = client.get("/openapi.json").json()
    actual_paths = {path: set(info.keys()) for path, info in openapi["paths"].items()}
    assert actual_paths == expected_paths
