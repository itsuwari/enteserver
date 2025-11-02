from __future__ import annotations

import datetime as dt
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..models import Collection, File, CollectionShare, PublicCollectionLink, User
from ..schemas import (
    CollectionCreate,
    CollectionResponse,
    CollectionShareRequest,
    CollectionUnshareRequest,
    CollectionJoinLinkRequest,
    ShareesResponse,
    ShareeResponse,
    CollectionAddFilesRequest,
    CollectionMoveFilesRequest,
    CollectionRemoveFilesRequest,
    CollectionRemoveFilesV3Request,
    CollectionRenameRequest,
    CollectionMagicMetadataUpdateRequest,
    CollectionShareURLRequest,
    CollectionShareURLUpdateRequest,
    CollectionShareURLResult,
)
from ..security import get_current_user

router = APIRouter(prefix="/collections", tags=["collections"])


def _now_us() -> int:
    return int(dt.datetime.utcnow().timestamp() * 1_000_000)


def _microseconds_to_dt(value: Optional[int]) -> Optional[dt.datetime]:
    if value in (None, 0):
        return None
    return dt.datetime.utcfromtimestamp(value / 1_000_000)


def _collection_to_response(collection: Collection) -> CollectionResponse:
    return CollectionResponse(
        id=collection.id,
        name=collection.name,
        created_at=collection.created_at,
        updated_at=collection.updated_at,
        collection_type=collection.collection_type,
        is_shared=collection.is_shared or False,
        is_pinned=collection.is_pinned or False,
        encrypted_key=collection.encrypted_key,
        key_decryption_nonce=collection.key_decryption_nonce,
        encrypted_name=collection.encrypted_name,
        name_decryption_nonce=collection.name_decryption_nonce,
    )


def _user_has_access(db: Session, collection: Collection, user: User) -> bool:
    if collection.owner_id == user.id:
        return True
    share = (
        db.query(CollectionShare)
        .filter(
            CollectionShare.collection_id == collection.id,
            CollectionShare.status == "active",
            CollectionShare.sharee_user_id == user.id,
        )
        .one_or_none()
    )
    return share is not None


def _get_owned_collection(db: Session, collection_id: int, user: User) -> Collection:
    collection = db.get(Collection, collection_id)
    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")
    if collection.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Only the owner may perform this action")
    return collection


def _share_entry_to_response(db: Session, entry: CollectionShare) -> ShareeResponse:
    sharee_user = db.get(User, entry.sharee_user_id) if entry.sharee_user_id else None
    email = sharee_user.email if sharee_user else entry.email
    name = getattr(sharee_user, "name", None) if sharee_user else None
    role = (entry.role or "viewer").upper()
    return ShareeResponse(id=entry.sharee_user_id, email=email, name=name, role=role)


def _sharees_for_collection(db: Session, collection_id: int) -> ShareesResponse:
    entries = (
        db.query(CollectionShare)
        .filter(
            CollectionShare.collection_id == collection_id,
            CollectionShare.status == "active",
        )
        .all()
    )
    return ShareesResponse(sharees=[_share_entry_to_response(db, entry) for entry in entries])


def _ensure_public_link(db: Session, collection_id: int) -> PublicCollectionLink:
    link = (
        db.query(PublicCollectionLink)
        .filter(PublicCollectionLink.collection_id == collection_id)
        .one_or_none()
    )
    if link:
        return link
    link = PublicCollectionLink(
        collection_id=collection_id,
        token=uuid.uuid4().hex,
        allow_upload=False,
    )
    db.add(link)
    db.flush()
    return link


def _public_link_to_result(link: PublicCollectionLink) -> CollectionShareURLResult:
    base_url = (settings.albums_base_url or "").rstrip("/")
    if base_url:
        url = f"{base_url}/{link.token}"
    else:
        url = f"/albums/collection/{link.token}"
    valid_till = None
    if link.expires_at is not None:
        valid_till = int(link.expires_at.timestamp() * 1_000_000)
    return CollectionShareURLResult(
        url=url,
        device_limit=link.device_limit or 0,
        valid_till=valid_till,
        enable_download=bool(link.enable_download),
        enable_join=bool(link.enable_join),
        enable_collect=bool(link.enable_collect),
        password_enabled=bool(link.password_hash),
        nonce=link.nonce,
        mem_limit=link.mem_limit,
        ops_limit=link.ops_limit,
    )


def _parse_since_time(since: Optional[str]) -> dt.datetime:
    if since is None or str(since).strip() == "":
        return dt.datetime.utcfromtimestamp(0)
    s = str(since).strip()
    if s.isdigit():
        us = int(s)
        return dt.datetime.utcfromtimestamp(us / 1_000_000.0)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dtobj = dt.datetime.fromisoformat(s)
        if dtobj.tzinfo is not None:
            dtobj = dtobj.astimezone(dt.timezone.utc).replace(tzinfo=None)
        return dtobj
    except Exception as exc:
        raise HTTPException(status_code=400, detail="sinceTime must be microseconds or ISO8601") from exc


@router.post("", response_model=CollectionResponse)
def create_collection(
    payload: CollectionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    collection = Collection(owner_id=current_user.id, name=payload.name)
    db.add(collection)
    db.commit()
    db.refresh(collection)
    return _collection_to_response(collection)


@router.get("", response_model=list[CollectionResponse])
def list_collections(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = db.query(Collection).filter(Collection.owner_id == current_user.id).all()
    return [_collection_to_response(row) for row in rows]


@router.get("/{collection_id}", response_model=CollectionResponse)
def get_collection(
    collection_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    collection = db.get(Collection, collection_id)
    if not collection or not _user_has_access(db, collection, current_user):
        raise HTTPException(status_code=404, detail="Collection not found")
    return _collection_to_response(collection)


@router.get("/v2")
def list_collections_delta(
    sinceTime: Optional[str] = Query(default=None, description="microseconds since epoch or ISO8601"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    since_dt = _parse_since_time(sinceTime)
    rows = db.query(Collection).filter(
        Collection.owner_id == current_user.id,
        Collection.updated_at >= since_dt,
    ).all()
    server_time_us = _now_us()
    items = [
        {
            "id": c.id,
            "name": c.name,
            "updatedAtUs": int((c.updated_at or dt.datetime.utcnow()).timestamp() * 1_000_000),
        }
        for c in rows
    ]
    next_since = max([item["updatedAtUs"] for item in items], default=server_time_us)
    return {"serverTime": server_time_us, "nextSince": next_since, "collections": items}


@router.post("/share", response_model=ShareesResponse)
def share_collection(
    payload: CollectionShareRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    collection = _get_owned_collection(db, payload.collection_id, current_user)
    share = (
        db.query(CollectionShare)
        .filter(
            CollectionShare.collection_id == collection.id,
            CollectionShare.email == payload.email,
        )
        .one_or_none()
    )
    sharee_user = db.query(User).filter(User.email == payload.email).one_or_none()
    role = (payload.role or "viewer").lower()
    if share:
        share.encrypted_key = payload.encrypted_key or share.encrypted_key
        share.role = role
        share.status = "active"
        if sharee_user:
            share.sharee_user_id = sharee_user.id
    else:
        share = CollectionShare(
            collection_id=collection.id,
            owner_id=current_user.id,
            sharee_user_id=sharee_user.id if sharee_user else None,
            email=payload.email,
            encrypted_key=payload.encrypted_key,
            role=role,
        )
        db.add(share)
    db.commit()
    return _sharees_for_collection(db, collection.id)


@router.post("/unshare", response_model=ShareesResponse)
def unshare_collection(
    payload: CollectionUnshareRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    collection = _get_owned_collection(db, payload.collection_id, current_user)
    share = (
        db.query(CollectionShare)
        .filter(
            CollectionShare.collection_id == collection.id,
            CollectionShare.email == payload.email,
        )
        .one_or_none()
    )
    if share:
        db.delete(share)
        db.commit()
    return _sharees_for_collection(db, collection.id)


@router.get("/sharees", response_model=ShareesResponse)
def get_sharees(
    collection_id: int = Query(..., alias="collectionID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    collection = db.get(Collection, collection_id)
    if not collection or collection.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Collection not found")
    return _sharees_for_collection(db, collection.id)


@router.post("/add-files")
def add_files_to_collection(
    payload: CollectionAddFilesRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    collection = _get_owned_collection(db, payload.collection_id, current_user)
    file_map = {item.id: item for item in payload.files}
    files = db.query(File).filter(File.id.in_(file_map.keys())).all()
    if len(files) != len(file_map):
        raise HTTPException(status_code=404, detail="One or more files not found")
    for file in files:
        if file.owner_id != current_user.id:
            raise HTTPException(status_code=403, detail=f"Cannot add file {file.id} owned by another user")
        item = file_map[file.id]
        file.collection_id = collection.id
        file.encrypted_key = item.encrypted_key
        file.key_decryption_nonce = item.key_decryption_nonce
        file.updated_at = dt.datetime.utcnow()
    db.commit()
    return {"added": len(files)}


@router.post("/move-files")
def move_files_between_collections(
    payload: CollectionMoveFilesRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _get_owned_collection(db, payload.from_collection_id, current_user)
    _get_owned_collection(db, payload.to_collection_id, current_user)
    file_map = {item.id: item for item in payload.files}
    files = db.query(File).filter(File.id.in_(file_map.keys())).all()
    if len(files) != len(file_map):
        raise HTTPException(status_code=404, detail="One or more files not found")
    for file in files:
        if file.owner_id != current_user.id or file.collection_id != payload.from_collection_id:
            raise HTTPException(status_code=403, detail=f"Cannot move file {file.id}")
        item = file_map[file.id]
        file.collection_id = payload.to_collection_id
        file.encrypted_key = item.encrypted_key
        file.key_decryption_nonce = item.key_decryption_nonce
        file.updated_at = dt.datetime.utcnow()
    db.commit()
    return {"moved": len(files)}


@router.post("/restore-files")
def restore_files(
    payload: CollectionRemoveFilesRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    collection = _get_owned_collection(db, payload.collection_id, current_user)
    files = db.query(File).filter(File.id.in_(payload.file_ids)).all()
    restored = 0
    for file in files:
        if file.owner_id != current_user.id or file.collection_id != collection.id:
            continue
        file.is_trashed = False
        file.trashed_at = None
        file.updated_at = dt.datetime.utcnow()
        restored += 1
    db.commit()
    return {"restored": restored}


@router.post("/v3/remove-files")
def remove_files_v3(
    payload: CollectionRemoveFilesV3Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    collection = _get_owned_collection(db, payload.collection_id, current_user)
    files = db.query(File).filter(File.id.in_(payload.file_ids)).all()
    removed = 0
    for file in files:
        if file.collection_id == collection.id:
            file.collection_id = None
            file.updated_at = dt.datetime.utcnow()
            removed += 1
    db.commit()
    return {"removed": removed}


@router.delete("/v3/{collection_id}")
def delete_collection_v3(
    collection_id: int,
    keepFiles: str = Query("false"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    collection = _get_owned_collection(db, collection_id, current_user)
    keep_files = keepFiles.lower() in {"true", "1", "yes"}
    files = db.query(File).filter(File.collection_id == collection.id).all()
    now = dt.datetime.utcnow()
    for file in files:
        if keep_files:
            file.collection_id = None
        else:
            file.is_trashed = True
            file.trashed_at = now
        file.updated_at = now
    db.delete(collection)
    db.commit()
    return {"deleted": True}


@router.post("/rename")
def rename_collection(
    payload: CollectionRenameRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    collection = _get_owned_collection(db, payload.collection_id, current_user)
    collection.encrypted_name = payload.encrypted_name
    collection.name_decryption_nonce = payload.name_decryption_nonce
    collection.updated_at = dt.datetime.utcnow()
    db.commit()
    return {"collectionID": collection.id, "updatedAt": _now_us()}


@router.put("/magic-metadata")
def update_collection_magic_metadata(
    payload: CollectionMagicMetadataUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    collection = _get_owned_collection(db, payload.id, current_user)
    collection.magic_metadata_header = payload.magic_metadata.header
    collection.magic_metadata_data = payload.magic_metadata.data
    collection.magic_metadata_version = payload.magic_metadata.version
    collection.updated_at = dt.datetime.utcnow()
    db.commit()
    return {"updated": True}


@router.put("/public-magic-metadata")
def update_collection_public_magic_metadata(
    payload: CollectionMagicMetadataUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    collection = _get_owned_collection(db, payload.id, current_user)
    collection.pub_magic_metadata_header = payload.magic_metadata.header
    collection.pub_magic_metadata_data = payload.magic_metadata.data
    collection.pub_magic_metadata_version = payload.magic_metadata.version
    collection.updated_at = dt.datetime.utcnow()
    db.commit()
    return {"updated": True}


@router.put("/sharee-magic-metadata")
def update_collection_sharee_magic_metadata(
    payload: CollectionMagicMetadataUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    share = (
        db.query(CollectionShare)
        .filter(
            CollectionShare.collection_id == payload.id,
            CollectionShare.sharee_user_id == current_user.id,
            CollectionShare.status == "active",
        )
        .one_or_none()
    )
    if not share:
        raise HTTPException(status_code=404, detail="Share not found")
    share.magic_metadata_header = payload.magic_metadata.header
    share.magic_metadata_data = payload.magic_metadata.data
    share.magic_metadata_version = payload.magic_metadata.version
    share.updated_at = dt.datetime.utcnow()
    db.commit()
    return {"updated": True}


@router.post("/share-url")
def create_share_url(
    payload: CollectionShareURLRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _get_owned_collection(db, payload.collection_id, current_user)
    link = _ensure_public_link(db, payload.collection_id)
    if payload.device_limit is not None:
        link.device_limit = payload.device_limit
    if payload.valid_till:
        link.expires_at = _microseconds_to_dt(payload.valid_till)
    link.enable_download = bool(payload.enable_download) if payload.enable_download is not None else link.enable_download
    link.enable_collect = bool(payload.enable_collect) if payload.enable_collect is not None else link.enable_collect
    link.allow_upload = link.enable_collect
    link.enable_join = bool(payload.enable_join) if payload.enable_join is not None else link.enable_join
    link.password_hash = payload.pass_hash or link.password_hash
    link.nonce = payload.nonce or link.nonce
    link.mem_limit = payload.mem_limit if payload.mem_limit is not None else link.mem_limit
    link.ops_limit = payload.ops_limit if payload.ops_limit is not None else link.ops_limit
    link.updated_at = dt.datetime.utcnow()
    db.commit()
    db.refresh(link)
    result = _public_link_to_result(link)
    return {"result": result.model_dump(by_alias=True)}


@router.put("/share-url")
def update_share_url(
    payload: CollectionShareURLUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _get_owned_collection(db, payload.collection_id, current_user)
    link = _ensure_public_link(db, payload.collection_id)
    if payload.device_limit is not None:
        link.device_limit = payload.device_limit
    if payload.valid_till is not None:
        link.expires_at = _microseconds_to_dt(payload.valid_till)
    if payload.enable_download is not None:
        link.enable_download = bool(payload.enable_download)
    if payload.enable_collect is not None:
        link.enable_collect = bool(payload.enable_collect)
        link.allow_upload = link.enable_collect
    if payload.enable_join is not None:
        link.enable_join = bool(payload.enable_join)
    if payload.disable_password:
        link.password_hash = None
        link.nonce = None
        link.mem_limit = None
        link.ops_limit = None
    else:
        if payload.pass_hash is not None:
            link.password_hash = payload.pass_hash
        if payload.nonce is not None:
            link.nonce = payload.nonce
        if payload.mem_limit is not None:
            link.mem_limit = payload.mem_limit
        if payload.ops_limit is not None:
            link.ops_limit = payload.ops_limit
    link.updated_at = dt.datetime.utcnow()
    db.commit()
    db.refresh(link)
    result = _public_link_to_result(link)
    return {"result": result.model_dump(by_alias=True)}


@router.delete("/share-url/{collection_id}")
def delete_share_url(
    collection_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _get_owned_collection(db, collection_id, current_user)
    link = (
        db.query(PublicCollectionLink)
        .filter(PublicCollectionLink.collection_id == collection_id)
        .one_or_none()
    )
    if link:
        db.delete(link)
        db.commit()
    return {"deleted": True}


@router.post("/join-link")
def join_collection_via_link(
    payload: CollectionJoinLinkRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    link = (
        db.query(PublicCollectionLink)
        .filter(PublicCollectionLink.collection_id == payload.collection_id)
        .one_or_none()
    )
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    collection = db.get(Collection, payload.collection_id)
    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")
    share = (
        db.query(CollectionShare)
        .filter(
            CollectionShare.collection_id == payload.collection_id,
            CollectionShare.sharee_user_id == current_user.id,
        )
        .one_or_none()
    )
    if not share:
        share = CollectionShare(
            collection_id=payload.collection_id,
            owner_id=collection.owner_id,
            sharee_user_id=current_user.id,
            email=current_user.email,
            encrypted_key=payload.encrypted_key,
            role="viewer",
        )
        db.add(share)
    else:
        share.encrypted_key = payload.encrypted_key or share.encrypted_key
        share.status = "active"
    db.commit()
    return {}


@router.post("/leave/{collection_id}")
def leave_shared_collection(
    collection_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    share = (
        db.query(CollectionShare)
        .filter(
            CollectionShare.collection_id == collection_id,
            CollectionShare.sharee_user_id == current_user.id,
        )
        .one_or_none()
    )
    if share:
        db.delete(share)
        db.commit()
    return {"left": True}
