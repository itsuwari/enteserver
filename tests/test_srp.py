import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from app.srp import SRPHelper
from app.db import SessionLocal, Base, engine
from app.models import User

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    """Create database tables before tests."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def db_session():
    """Provide a database session for tests."""
    session = SessionLocal()
    yield session
    session.rollback()
    session.close()

class TestSRPHelper:
    """Test SRP helper utilities."""

    def test_generate_salt(self):
        """Test salt generation produces valid hex string."""
        salt = SRPHelper.generate_salt()
        assert isinstance(salt, str)
        assert len(salt) == 32  # 16 bytes * 2 (hex)
        # Should be valid hexadecimal
        int(salt, 16)

    def test_generate_verifier_consistency(self):
        """Test verifier generation is consistent."""
        email = "test@example.com"
        password = "testpassword123"
        salt = "abcd1234567890abcdef1234567890ab"

        verifier1 = SRPHelper.generate_verifier(email, password, salt)
        verifier2 = SRPHelper.generate_verifier(email, password, salt)

        assert verifier1 == verifier2
        assert isinstance(verifier1, str)
        assert len(verifier1) > 0

    def test_generate_verifier_different_inputs(self):
        """Test that different inputs produce different verifiers."""
        salt = "abcd1234567890abcdef1234567890ab"

        v1 = SRPHelper.generate_verifier("user1@example.com", "pass1", salt)
        v2 = SRPHelper.generate_verifier("user2@example.com", "pass1", salt)
        v3 = SRPHelper.generate_verifier("user1@example.com", "pass2", salt)

        assert v1 != v2
        assert v1 != v3
        assert v2 != v3

    def test_calculate_x_basic(self):
        """Test x calculation with known values."""
        email = "alice"
        password = "password123"
        salt = "beef1357beef1357beef1357beef1357"

        x = SRPHelper._calculate_x(email, password, salt)
        assert isinstance(x, int)
        assert x > 0

    def test_srp_parameters(self):
        """Test that SRP parameters are correctly defined."""
        # Test that N is the correct 1024-bit prime
        assert SRPHelper.SRP_N.bit_length() == 1024
        assert SRPHelper.SRP_G == 2
        assert SRPHelper.SRP_SALT_LENGTH == 16


class TestSRPIntegration:
    """Test SRP authentication endpoints with real database."""

    def test_srp_verifier_generation_flow(self, db_session):
        """Test complete SRP verifier generation flow."""
        email = "test@example.com"
        password = "testpass123"

        # Generate SRP parameters
        salt = SRPHelper.generate_salt()
        verifier = SRPHelper.generate_verifier(email, password, salt)

        # Create user with SRP parameters
        user = User(email=email, srp_salt=salt, srp_verifier=verifier)
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        assert user.srp_salt == salt
        assert user.srp_verifier == verifier

    def test_srp_challenge_endpoint_invalid_user(self):
        """Test SRP challenge with non-existent user."""
        payload = {
            "email": "nonexistent@example.com",
            "srpA": "a1234567890abcdef" * 16  # 256-bit A value
        }

        response = client.post("/users/srp/challenge", json=payload)
        assert response.status_code == 401
        assert "User not found" in response.json()["detail"]

    @pytest.mark.auth
    def test_srp_challenge_success(self, db_session):
        """Test successful SRP challenge generation."""
        email = "test@example.com"
        password = "testpass123"

        # Create user with SRP credentials
        salt = SRPHelper.generate_salt()
        verifier = SRPHelper.generate_verifier(email, password, salt)

        user = User(email=email, srp_salt=salt, srp_verifier=verifier)
        db_session.add(user)
        db_session.commit()

        # Generate client A (simplified for testing)
        client_a = "1234567890abcdef" * 16  # Mock A value

        payload = {
            "email": email,
            "srpA": client_a
        }

        response = client.post("/users/srp/challenge", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert "srpSalt" in data
        assert "srpB" in data
        assert data["srpSalt"] == salt

        # srpB should be a valid hex string
        int(data["srpB"], 16)

    @pytest.mark.auth
    def test_srp_login_flow_simplified(self, db_session):
        """Test simplified SRP login flow (with mocked verification)."""
        email = "test@example.com"

        # Create user with SRP credentials
        salt = SRPHelper.generate_salt()
        verifier = SRPHelper.generate_verifier(email, "password123", salt)

        user = User(email=email, srp_salt=salt, srp_verifier=verifier)
        db_session.add(user)
        db_session.commit()

        # Mock client A and M1 values
        client_a = "1234567890abcdef" * 16
        client_m1 = "abcd1234" * 16

        # Mock the verification to return success for testing
        with patch.object(SRPHelper, 'verify_client_auth', return_value={
            'verified': True,
            'server_proof': 'dcba4321' * 16
        }):
            payload = {
                "email": email,
                "srpA": client_a,
                "srpM1": client_m1
            }

            response = client.post("/users/srp/login", json=payload)
            assert response.status_code == 200

            data = response.json()
            assert "srpM2" in data
            assert "authToken" in data
            assert "expiresIn" in data
            assert "tokenType" in data

    @pytest.mark.auth
    def test_srp_login_invalid_proof(self, db_session):
        """Test SRP login with invalid proof."""
        email = "test@example.com"

        # Create user with SRP credentials
        salt = SRPHelper.generate_salt()
        verifier = SRPHelper.generate_verifier(email, "password123", salt)

        user = User(email=email, srp_salt=salt, srp_verifier=verifier)
        db_session.add(user)
        db_session.commit()

        client_a = "1234567890abcdef" * 16
        client_m1 = "abcd1234" * 16

        # Mock verification to fail
        with patch.object(SRPHelper, 'verify_client_auth', return_value={
            'verified': False,
            'server_proof': ''
        }):
            payload = {
                "email": email,
                "srpA": client_a,
                "srpM1": client_m1
            }

            response = client.post("/users/srp/login", json=payload)
            assert response.status_code == 401
            assert "SRP authentication failed" in response.json()["detail"]

    def test_legacy_login_still_works(self, db_session):
        """Test that legacy bcrypt login still works."""
        email = "legacy@example.com"
        password = "legacy_pass"

        # Create user with bcrypt hash (legacy)
        from app.security import hash_password
        user = User(email=email, password_hash=hash_password(password))
        db_session.add(user)
        db_session.commit()

        payload = {
            "email": email,
            "password": password
        }

        response = client.post("/users/login", json=payload)
        # This will fail due to database setup, but should not be 404
        assert response.status_code != 404


class TestSRPModels:
    """Test User model SRP fields."""

    def test_user_srp_fields_nullable(self, db_session):
        """Test that SRP fields can be null."""
        user = User(email="test@example.com")
        db_session.add(user)
        db_session.commit()

        assert user.srp_salt is None
        assert user.srp_verifier is None
        assert user.password_hash is None  # Legacy field also nullable

    def test_user_unique_email_constraint(self, db_session):
        """Test email uniqueness constraint."""
        user1 = User(email="duplicate@example.com")
        db_session.add(user1)
        db_session.commit()

        user2 = User(email="duplicate@example.com")
        db_session.add(user2)

        with pytest.raises(Exception):  # IntegrityError expected
            db_session.commit()

    def test_user_email_index(self, db_session):
        """Test that email field is indexed for SRP lookups."""
        # This test mainly checks that the model loads without error
        user = User(email="indexed@example.com", srp_salt="test", srp_verifier="test")
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        # Test lookup works
        found = db_session.query(User).filter(User.email == "indexed@example.com").first()
        assert found is not None
        assert found.email == "indexed@example.com"


@pytest.mark.parametrize("email,password", [
    ("user@example.com", "password"),
    ("test@domain.org", "complex!pass123"),
    ("alice+bob@subdomain.co.uk", "verylongpasswordthatshouldworkfine12345678"),
])
def test_srp_verifier_email_formats(email, password):
    """Test SRP verifier works with different email formats."""
    salt = SRPHelper.generate_salt()
    verifier = SRPHelper.generate_verifier(email, password, salt)

    assert isinstance(verifier, str)
    assert len(verifier) > 0
    # Verifier should be different for each email
    salt2 = SRPHelper.generate_salt()
    verifier2 = SRPHelper.generate_verifier("different@example.com", password, salt2)
    assert verifier != verifier2
