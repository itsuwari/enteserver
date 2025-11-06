"""Authentication flow tests covering legacy password login."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app
from app.models import User, UserSession
from app.security import hash_password
import secrets
import uuid


@pytest.fixture()
def session_factory(tmp_path):
    """Provide an isolated SQLite database for each test."""

    db_path = tmp_path / "auth_test.db"
    engine = create_engine(
        f"sqlite:///{db_path}", connect_args={"check_same_thread": False}
    )
    TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    try:
        yield TestingSessionLocal
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture()
def client(session_factory):
    """FastAPI test client bound to the isolated database."""

    previous_override = app.dependency_overrides.get(get_db)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client

    if previous_override is not None:
        app.dependency_overrides[get_db] = previous_override
    else:
        app.dependency_overrides.pop(get_db, None)


def _create_user(session_factory, email: str, password: str | None = None) -> tuple[int, str]:
    """Seed a user with randomised credentials and return (id, password)."""

    session = session_factory()
    try:
        assigned_password = password or secrets.token_urlsafe(12)
        user = User(email=email, password_hash=hash_password(assigned_password))
        user.id = secrets.randbits(31)
        session.add(user)
        session.commit()
        session.refresh(user)
        return int(user.id), assigned_password
    finally:
        session.close()


def _list_sessions(session_factory):
    session = session_factory()
    try:
        return session.query(UserSession).all()
    finally:
        session.close()


def test_password_login_success(client, session_factory):
    email = f"login-success-{uuid.uuid4().hex}@example.com"
    user_id, password = _create_user(session_factory, email)

    response = client.post(
        "/users/login",
        json={"email": email, "password": password},
    )

    assert response.status_code == 200
    data = response.json()
    assert set(data.keys()) == {"authToken", "tokenType", "expiresIn"}
    assert data["tokenType"].lower() == "bearer"
    assert data["expiresIn"] == 24 * 3600
    assert isinstance(data["authToken"], str) and data["authToken"]

    sessions = _list_sessions(session_factory)
    assert len(sessions) == 1
    assert sessions[0].user_id == user_id
    assert sessions[0].revoked is False


def test_password_login_invalid_password(client, session_factory):
    email = f"login-fail-{uuid.uuid4().hex}@example.com"
    _user_id, _ = _create_user(session_factory, email, "CorrectHorseBatteryStaple")

    response = client.post(
        "/users/login",
        json={"email": email, "password": "wrong-password"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"

    sessions = _list_sessions(session_factory)
    assert sessions == []
