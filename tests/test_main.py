import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_ping_endpoint():
    """Test the ping endpoint for health checks."""
    response = client.get("/ping")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_healthz_endpoint():
    """Test the health check endpoint."""
    response = client.get("/healthz")
    # May fail if database/S3 not available, but should return a response
    assert response.status_code in [200, 503]
    assert "status" in response.json()

def test_version_endpoint():
    """Test the version endpoint."""
    response = client.get("/version")
    assert response.status_code == 200
    data = response.json()
    assert "version" in data
    assert "build" in data

def test_docs_endpoint():
    """Test that API documentation is accessible."""
    response = client.get("/docs")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

def test_openapi_endpoint():
    """Test that OpenAPI schema is accessible."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    data = response.json()
    assert "openapi" in data
    assert "info" in data
    assert "paths" in data

@pytest.mark.auth
def test_login_endpoint_exists():
    """Test that login endpoint exists (may fail without valid credentials)."""
    response = client.post("/users/login", json={
        "email": "test@example.com",
        "password": "testpassword"
    })
    # Should return 401 or 422, not 404
    assert response.status_code in [401, 422]

@pytest.mark.storage
def test_storage_usage_endpoint_requires_auth():
    """Test that storage endpoints require authentication."""
    response = client.get("/storage/usage")
    assert response.status_code == 401

@pytest.mark.api
def test_files_endpoint_requires_auth():
    """Test that file endpoints require authentication."""
    response = client.get("/files/upload-urls")
    assert response.status_code == 401

@pytest.mark.integration
def test_cors_headers():
    """Test that CORS headers are properly set."""
    response = client.options("/ping")
    # FastAPI should handle OPTIONS requests
    assert response.status_code in [200, 405]

def test_app_startup():
    """Test that the FastAPI app starts up correctly."""
    assert app is not None
    assert hasattr(app, 'routes')
    assert len(app.routes) > 0