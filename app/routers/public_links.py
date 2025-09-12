
from __future__ import annotations
import datetime as dt, secrets
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import PublicCollectionLink, PublicFileLink, Collection, File, User
from ..schemas import PublicCollectionCreate, PublicLinkResponse, FileCreate
from ..security import get_current_user
from ..config import settings
from ..s3 import presign_get, head_object_size_and_etag

router = APIRouter(prefix="/public", tags=["public-links"])

def _tok() -> str:
    return secrets.token_urlsafe(16)

@router.post("/collections", response_model=PublicLinkResponse)
def create_public_collection_link(payload: PublicCollectionCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    col = db.get(Collection, payload.collection_id)
    if not col or col.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Collection not found")
    token = _tok()
    link = PublicCollectionLink(
        token=token, collection_id=col.id, allow_upload=payload.allow_upload,
        password_hash=None if not payload.password else payload.password,
        expires_at=(dt.datetime.utcnow() + dt.timedelta(seconds=payload.expires_in_seconds)) if payload.expires_in_seconds else None
    )
    db.add(link); db.commit()
    return PublicLinkResponse(token=token, url=f"/albums/collection/{token}")

def _validate_collection_token(db: Session, token: str) -> PublicCollectionLink:
    link = db.query(PublicCollectionLink).filter(PublicCollectionLink.token == token).first()
    if not link: raise HTTPException(status_code=404, detail="Invalid link")
    if link.expires_at and link.expires_at < dt.datetime.utcnow():
        raise HTTPException(status_code=404, detail="Link expired")
    return link

@router.get("/collections/{token}")
def public_collection_redirect(token: str):
    return RedirectResponse(url=f"{settings.albums_base_url.rstrip('/')}/{token}", status_code=307)

@router.get("/collections/{token}/preview/{file_id}")
def public_preview(token: str, file_id: int, db: Session = Depends(get_db)):
    link = _validate_collection_token(db, token)
    f = db.get(File, file_id)
    if not f or f.collection_id != link.collection_id:
        raise HTTPException(status_code=404, detail="Not found")
    return RedirectResponse(url=presign_get(f.thumbnail_object_key or f.file_object_key), status_code=307)

@router.get("/files/{token}")
def public_file_redirect(token: str, db: Session = Depends(get_db)):
    link = db.query(PublicFileLink).filter(PublicFileLink.token == token).first()
    if not link: raise HTTPException(status_code=404, detail="Invalid link")
    f = db.get(File, link.file_id)
    if not f: raise HTTPException(status_code=404, detail="Not found")
    return RedirectResponse(url=presign_get(f.file_object_key), status_code=307)

@router.post("/collections/{token}/commit-file")
def public_collection_commit_file(token: str, payload: FileCreate, db: Session = Depends(get_db)):
    link = _validate_collection_token(db, token)
    if not link.allow_upload: raise HTTPException(status_code=403, detail="Uploads disabled")
    size, _ = head_object_size_and_etag(payload.file.object_key)
    if size is None:
        raise HTTPException(status_code=400, detail="Object not found or inaccessible in S3")
    col = db.get(Collection, link.collection_id)
    f = File(
        owner_id=col.owner_id,
        collection_id=link.collection_id,
        file_object_key=payload.file.object_key,
        thumbnail_object_key=payload.thumbnail.object_key if payload.thumbnail else None,
        encrypted_key=payload.encrypted_key,
        key_decryption_nonce=payload.key_decryption_nonce,
        metadata_header=payload.metadata.decryption_header if payload.metadata else None,
        metadata_encrypted_data=payload.metadata.encrypted_data if payload.metadata else None,
        magic_metadata_header=(payload.magic_metadata.header if payload.magic_metadata else (payload.pub_magic_metadata.header if payload.pub_magic_metadata else None)),
        magic_metadata_data=(payload.magic_metadata.data if payload.magic_metadata else (payload.pub_magic_metadata.data if payload.pub_magic_metadata else None)),
        mime_type=payload.mime_type,
        original_filename=payload.original_filename,
        size=size,
        sha256=payload.sha256,
    )
    db.add(f); db.commit(); db.refresh(f)
    return {"fileId": f.id}
