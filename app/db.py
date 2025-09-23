
from __future__ import annotations
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from .config import settings, reload_settings
import os

Base = declarative_base()

# Support dynamic DATABASE_URL changes during tests by recreating engine/session on demand
_DB_URL = None
engine = None
SessionLocal = None


def _init_engine(url: str):
    global engine, SessionLocal, _DB_URL
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, connect_args=connect_args)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    _DB_URL = url


def _ensure_engine_current():
    global _DB_URL
    # Prefer live environment variable if provided
    env_url = os.getenv("DATABASE_URL")
    url = env_url or settings.database_url
    # If config is stale vs env, reload settings to keep them in sync
    if env_url and settings.database_url != env_url:
        try:
            reload_settings()
        except Exception:
            pass
    if _DB_URL != url:
        # Dispose previous engine if present and re-init
        if engine is not None:
            try:
                engine.dispose()
            except Exception:
                pass
        _init_engine(url)


# Initialize on module import
_ensure_engine_current()

def get_db():
    from sqlalchemy.orm import Session
    _ensure_engine_current()
    # Lazily initialize if not set yet
    if SessionLocal is None:
        _init_engine(settings.database_url)
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ensure_tables(db=None):
    """
    Ensure all ORM tables exist for the bound engine.
    Helpful in tests where dependency overrides point to a different engine
    that hasn't had create_all() run yet.
    """
    try:
        bind = None
        if db is not None:
            try:
                bind = db.get_bind()
            except Exception:
                bind = None
        if bind is None:
            _ensure_engine_current()
            bind = engine
        if bind is not None:
            Base.metadata.create_all(bind=bind)
    except Exception:
        # Best-effort; don't block requests if table creation fails here
        pass
