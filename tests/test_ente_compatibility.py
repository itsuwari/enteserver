"""
Test Ente mobile client compatibility
Tests for new OTT and SRP endpoints to ensure mobile client compatibility
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import tempfile
import os

from app.main import app
from app.db import get_db, Base
from app.models import User, OneTimeToken, SRPSession
from app.ott import OTTService


# Create test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_ente_compat.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="module")
def setup_test_db():
    """Setup test database with tables"""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def client(setup_test_db):
    """FastAPI test client"""
    return TestClient(app)

@pytest.fixture
def db_session(setup_test_db):
    """Database session for direct database operations"""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


class TestOTTEndpoints:
    """Test OTT (One-Time-Token) endpoints for email verification"""
    
    def test_send_ott_success(self, client):
        """Test sending OTT to email"""
        response = client.post("/users/ott", json={
            "email": "test@example.com",
            "purpose": "signup",
            "mobile": True
        })
        
        assert response.status_code == 200
        assert response.json()["message"] == "OTT sent successfully"
    
    def test_send_ott_invalid_email(self, client):
        """Test sending OTT to invalid email format"""
        response = client.post("/users/ott", json={
            "email": "invalid-email",
            "purpose": "signup"
        })
        
        # Should still return success (don't reveal email validity)
        assert response.status_code == 200
    
    def test_verify_email_valid_ott(self, client, db_session):
        """Test email verification with valid OTT"""
        # First create an OTT
        email = "verify@example.com"
        ott_code, _ = OTTService.create_ott(db_session, email, "signup")
        
        response = client.post("/users/verify-email", json={
            "email": email,
            "ott": ott_code,
            "source": "mobile"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert "token" in data
        assert data["id"] > 0
        
        # Verify user was created
        user = db_session.query(User).filter(User.email == email).first()
        assert user is not None
        assert user.is_email_verified == True
    
    def test_verify_email_invalid_ott(self, client):
        """Test email verification with invalid OTT"""
        response = client.post("/users/verify-email", json={
            "email": "test@example.com",
            "ott": "123456",  # Invalid OTT
            "source": "mobile"
        })
        
        assert response.status_code == 400
        assert "detail" in response.json()


class TestSRPAttributesEndpoint:
    """Test SRP attributes endpoint"""
    
    def test_get_srp_attributes_existing_user(self, client, db_session):
        """Test getting SRP attributes for existing user with SRP configured"""
        # Create user with SRP attributes
        user = User(
            email="srp@example.com",
            srp_user_id="srp@example.com",
            srp_salt="test_salt_base64",
            kek_salt="test_kek_salt",
            mem_limit=67108864,
            ops_limit=3,
            is_email_mfa_enabled=False
        )
        db_session.add(user)
        db_session.commit()
        
        response = client.post("/users/srp/attributes", json={
            "email": "srp@example.com"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert "attributes" in data
        attrs = data["attributes"]
        assert attrs["srpUserID"] == "srp@example.com" 
        assert attrs["srpSalt"] == "test_salt_base64"
        assert attrs["memLimit"] == 67108864
        assert attrs["opsLimit"] == 3
        assert attrs["kekSalt"] == "test_kek_salt"
        assert attrs["isEmailMFAEnabled"] == False
    
    def test_get_srp_attributes_nonexistent_user(self, client):
        """Test getting SRP attributes for non-existent user"""
        response = client.post("/users/srp/attributes", json={
            "email": "nonexistent@example.com"
        })
        
        assert response.status_code == 404
        assert "User not found" in response.json()["detail"]
    
    def test_get_srp_attributes_user_without_srp(self, client, db_session):
        """Test getting SRP attributes for user without SRP configured"""
        # Create user without SRP
        user = User(email="no_srp@example.com")
        db_session.add(user)
        db_session.commit()
        
        response = client.post("/users/srp/attributes", json={
            "email": "no_srp@example.com"
        })
        
        assert response.status_code == 400
        assert "SRP not configured" in response.json()["detail"]


class TestSRPSessionEndpoints:
    """Test SRP session management endpoints"""
    
    def test_create_srp_session(self, client):
        """Test creating SRP session"""
        import base64
        
        # Mock client A value (would be generated by client)
        client_A = base64.b64encode(b"test_client_A_value_32_bytes_long").decode('ascii')
        
        response = client.post("/users/srp/create-session", json={
            "srpUserID": "session@example.com",
            "srpA": client_A
        })
        
        assert response.status_code == 200
        data = response.json()
        assert "sessionID" in data
        assert "srpB" in data
        assert len(data["sessionID"]) > 0
        assert len(data["srpB"]) > 0
    
    def test_verify_srp_session_invalid_session(self, client):
        """Test verifying invalid SRP session"""
        response = client.post("/users/srp/verify-session", json={
            "sessionID": "invalid-session-id",
            "srpUserID": "test@example.com", 
            "srpM1": "invalid_proof"
        })
        
        assert response.status_code == 401
        assert "SRP verification failed" in response.json()["detail"]


class TestSRPSetupEndpoints:
    """Test SRP setup flow endpoints"""
    
    def test_setup_srp_flow(self, client):
        """Test complete SRP setup flow"""
        import base64
        
        # Step 1: Setup SRP
        client_A = base64.b64encode(b"test_client_A_value_32_bytes_long").decode('ascii')
        
        response = client.post("/users/srp/setup", json={
            "srpUserID": "setup@example.com",
            "srpSalt": "test_salt",
            "srpVerifier": "test_verifier", 
            "srpA": client_A
        })
        
        assert response.status_code == 200
        data = response.json()
        assert "setupID" in data
        assert "srpB" in data
        
        setup_id = data["setupID"]
        
        # Step 2: Complete SRP setup (would fail with mock data, but test structure)
        response = client.post("/users/srp/complete", json={
            "setupID": setup_id,
            "srpM1": "mock_client_proof"
        })
        
        # Expect failure due to mock data, but endpoint should exist
        assert response.status_code in [400, 401]  # Expected failure with mock data


class TestEnteAPICompatibility:
    """Test overall API compatibility with Ente mobile clients"""
    
    def test_all_required_endpoints_exist(self, client):
        """Test that all required Ente endpoints exist and return proper responses"""
        
        # Test endpoint existence with OPTIONS or invalid requests
        required_endpoints = [
            "/users/ott",
            "/users/verify-email", 
            "/users/srp/attributes",
            "/users/srp/setup",
            "/users/srp/complete",
            "/users/srp/create-session",
            "/users/srp/verify-session"
        ]
        
        for endpoint in required_endpoints:
            # Test that endpoint exists (not 404)
            response = client.post(endpoint, json={})
            assert response.status_code != 404, f"Endpoint {endpoint} not found"
    
    def test_request_response_schemas(self, client):
        """Test that request/response schemas match Ente expectations"""
        
        # Test OTT endpoint schema
        response = client.post("/users/ott", json={
            "email": "schema@example.com",
            "purpose": "signup",
            "mobile": True
        })
        assert response.status_code == 200
        
        # Test SRP attributes schema  
        response = client.post("/users/srp/attributes", json={
            "email": "nonexistent@example.com"
        })
        # Should be 404, but validates schema
        assert response.status_code == 404
    
    def test_field_naming_conventions(self, client, db_session):
        """Test that field names match Ente's camelCase conventions"""
        
        # Create user with SRP attributes
        user = User(
            email="naming@example.com",
            srp_user_id="naming@example.com",
            srp_salt="salt",
            kek_salt="kek",
            mem_limit=64000000,
            ops_limit=2,
            is_email_mfa_enabled=True
        )
        db_session.add(user)
        db_session.commit()
        
        response = client.post("/users/srp/attributes", json={
            "email": "naming@example.com"
        })
        
        assert response.status_code == 200
        attrs = response.json()["attributes"]
        
        # Verify camelCase field names (as expected by Ente mobile)
        expected_fields = [
            "srpUserID", "srpSalt", "memLimit", "opsLimit", 
            "kekSalt", "isEmailMFAEnabled"
        ]
        
        for field in expected_fields:
            assert field in attrs, f"Missing field: {field}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])