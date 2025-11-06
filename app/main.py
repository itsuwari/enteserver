
from __future__ import annotations
from fastapi import FastAPI
from .db import Base, engine
from .routers.auth import router as auth_router
from .routers.files import router as files_router
from .routers.collections import router as collections_router
from .routers.public_links import public_router, public_collection_router, file_link_router
from .routers.kex import router as kex_router
from .routers.albums_redirect import router as albums_redirect_router
from .routers.trash import router as trash_router
from .routers.storage import router as storage_router
from .routers.admin_ui import router as admin_ui_router
from .routers.invite import router as invite_router
from .s3 import has_local_backend

app = FastAPI(title="Museum-subset (FastAPI) with S3 presign, sessions, trash")

Base.metadata.create_all(bind=engine)

app.include_router(auth_router)
app.include_router(files_router)
app.include_router(collections_router)
app.include_router(public_router)
app.include_router(public_collection_router)
app.include_router(file_link_router)
app.include_router(kex_router)
app.include_router(albums_redirect_router)
app.include_router(trash_router)
app.include_router(storage_router)
app.include_router(admin_ui_router)
app.include_router(invite_router)
if has_local_backend():
    from .routers.local_storage import router as local_storage_router

    app.include_router(local_storage_router)

@app.get("/ping")
def ping():
    return {"status": "ok"}


import os, datetime as dt
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from botocore.exceptions import BotoCoreError, ClientError
from .db import SessionLocal, engine
from .config import settings
from . import s3 as s3mod


@app.get("/version")
def version():
    """Return build/version information for the server."""
    return {
        "version": os.getenv("GIT_COMMIT", os.getenv("COMMIT", "unknown")),
        "build": os.getenv("BUILD_DATE", "unknown"),
    }


@app.get("/healthz")
def healthz():
    """Run simple checks for the database and S3."""
    db_status = "skipped"
    s3_status = "skipped"
    # DB ping
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_status = "ok"
    except SQLAlchemyError as e:
        db_status = f"error: {type(e).__name__}"
    # S3 ping
    try:
        if settings.s3_enabled:
            client = s3mod._client()
            bucket = s3mod._bucket()
            if bucket:
                client.generate_presigned_url("list_objects_v2", Params={"Bucket": bucket})
            s3_status = "ok"
    except (BotoCoreError, ClientError) as e:
        s3_status = f"error: {type(e).__name__}"
    server_time = int(dt.datetime.utcnow().timestamp() * 1_000_000)
    ok = (db_status in ("ok", "skipped")) and (s3_status in ("ok", "skipped"))
    status = "ok" if ok else "error"
    return {
        "status": status,
        "ok": ok,
        "db": db_status,
        "s3": s3_status,
        "serverTime": server_time,
    }
