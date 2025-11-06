from __future__ import annotations

import datetime as dt
import secrets
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
import jwt

from ..config import settings
from ..db import get_db
from ..models import (
    PublicCollectionLink,
    PublicFileLink,
    FileShareLink,
    Collection,
    File,
    User,
    FileDataEntry,
)
from ..schemas import (
    PublicCollectionCreate,
    PublicLinkResponse,
    FileCreate,
    UploadURL,
    MultipartUploadURLs,
    MultipartCompleteRequest,
    FileDataFetchResponse,
    FileDataItem,
    FileDataType,
)
from ..security import get_current_user
from .collections import (
    _file_attributes_payload,
    _magic_metadata_payload,
    _dt_to_microseconds,
)
from ..s3 import (
    presign_get,
    presign_put,
    mpu_init,
    mpu_presign_part,
    mpu_complete,
    head_object_size_and_etag,
    resolve_presigned_url,
)

public_router = APIRouter(prefix="/public", tags=["public-links"])
public_collection_router = APIRouter(prefix="/public-collection", tags=["public-collection"])
file_link_router = APIRouter(prefix="/file-link", tags=["file-link"])


def _tok() -> str:
    return secrets.token_urlsafe(16)


def _now_us() -> int:
    return int(dt.datetime.utcnow().timestamp() * 1_000_000)


def _access_jwt_from_request(request: Request) -> Optional[str]:
    token = request.headers.get("X-Auth-Access-Token-JWT")
    if not token:
        token = request.query_params.get("accessTokenJWT")
    return token or None


def _access_token_from_request(request: Request) -> Optional[str]:
    token = request.headers.get("X-Auth-Access-Token")
    if not token:
        token = request.query_params.get("accessToken")
    return token or None


def _issue_public_access_jwt(pass_hash: str) -> str:
    expiry_us = _now_us() + 365 * 24 * 60 * 60 * 1_000_000
    payload = {"passKey": pass_hash, "expiryTime": expiry_us}
    token = jwt.encode(payload, settings.jwt_secret, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def _validate_public_access_jwt(token: str, expected_hash: str) -> None:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=403, detail="Invalid access token") from exc

    if payload.get("passKey") != expected_hash:
        raise HTTPException(status_code=403, detail="Invalid access token")

    try:
        expiry_us = int(payload.get("expiryTime"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=403, detail="Invalid access token")

    if expiry_us < _now_us():
        raise HTTPException(status_code=403, detail="Access token expired")


def _require_public_link_jwt(link: PublicCollectionLink, request: Request) -> None:
    if not link.password_hash:
        return
    token = _access_jwt_from_request(request)
    if not token:
        raise HTTPException(status_code=401, detail="Missing access token")
    _validate_public_access_jwt(token, link.password_hash)


def _file_link_entry(
    db: Session,
    request: Request,
    *,
    allow_password_bypass: bool = False,
) -> FileShareLink:
    access_token = _access_token_from_request(request)
    if not access_token:
        raise HTTPException(status_code=401, detail="Missing access token")
    link = (
        db.query(FileShareLink)
        .filter(
            FileShareLink.token == access_token,
            FileShareLink.is_disabled.is_(False),
        )
        .one_or_none()
    )
    if not link:
        raise HTTPException(status_code=404, detail="Invalid or disabled link")
    if link.valid_till and link.valid_till < dt.datetime.utcnow():
        raise HTTPException(status_code=410, detail="Link expired")
    if link.pass_hash and not allow_password_bypass:
        jwt_token = _access_jwt_from_request(request)
        if not jwt_token:
            raise HTTPException(status_code=401, detail="Missing access token")
        _validate_public_access_jwt(jwt_token, link.pass_hash)
    return link


def _file_link_payload(db: Session, link: FileShareLink, file: File) -> dict:
    collection = db.get(Collection, file.collection_id) if file.collection_id else None
    magic_metadata = _magic_metadata_payload(
        file.magic_metadata_header,
        file.magic_metadata_data,
        file.magic_metadata_version,
        file.magic_metadata_count,
    )
    public_magic_metadata = _magic_metadata_payload(
        file.pub_magic_metadata_header,
        file.pub_magic_metadata_data,
        file.pub_magic_metadata_version,
        file.pub_magic_metadata_count,
    )
    info_payload = {
        "fileSize": file.size or 0,
        "thumbSize": file.thumbnail_size or 0,
    }
    collection_owner_id = collection.owner_id if collection else file.owner_id
    collection_id = collection.id if collection else (file.collection_id or 0)
    return {
        "id": file.id,
        "ownerID": file.owner_id,
        "collectionID": collection_id,
        "collectionOwnerID": collection_owner_id,
        "encryptedKey": file.encrypted_key or "",
        "keyDecryptionNonce": file.key_decryption_nonce or "",
        "file": _file_attributes_payload(
            file.file_object_key,
            getattr(file, "file_nonce", None),
            size=file.size,
        ),
        "thumbnail": _file_attributes_payload(
            file.thumbnail_object_key,
            getattr(file, "thumbnail_nonce", None),
            size=file.thumbnail_size,
        ),
        "metadata": _file_attributes_payload(
            None,
            file.metadata_header,
            encrypted_data=file.metadata_encrypted_data or "",
        ),
        "info": info_payload,
        "isDeleted": bool(file.is_trashed),
        "updationTime": _dt_to_microseconds(file.updated_at or file.created_at),
        "magicMetadata": magic_metadata,
        "pubMagicMetadata": public_magic_metadata,
    }


def _absolute_presign(url: str, request: Request) -> str:
    return resolve_presigned_url(url, str(request.base_url))


def _validate_collection_token(db: Session, token: str) -> PublicCollectionLink:
    link = (
        db.query(PublicCollectionLink)
        .filter(PublicCollectionLink.token == token)
        .one_or_none()
    )
    if not link:
        raise HTTPException(status_code=404, detail="Invalid link")
    if link.expires_at and link.expires_at < dt.datetime.utcnow():
        raise HTTPException(status_code=404, detail="Link expired")
    return link


def _link_from_headers(
    db: Session,
    request: Request,
    *,
    require_jwt: bool = True,
) -> PublicCollectionLink:
    token = request.headers.get("X-Auth-Access-Token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing X-Auth-Access-Token header")
    link = _validate_collection_token(db, token)
    if require_jwt:
        _require_public_link_jwt(link, request)
    return link


def _file_for_public_collection(
    db: Session,
    link: PublicCollectionLink,
    file_id: int,
) -> File:
    file = db.get(File, file_id)
    if not file or file.collection_id != link.collection_id:
        raise HTTPException(status_code=404, detail="File not found")
    return file


def _public_url_payload(link: PublicCollectionLink, request: Request | None = None) -> dict:
    base_url = (settings.albums_base_url or "").rstrip("/")
    url = f"{base_url}/{link.token}" if base_url else f"/albums/collection/{link.token}"
    valid_till = None
    if link.expires_at is not None:
        valid_till = int(link.expires_at.timestamp() * 1_000_000)
    return {
        "url": url,
        "deviceLimit": link.device_limit or 0,
        "validTill": valid_till or 0,
        "enableDownload": bool(link.enable_download),
        "enableCollect": bool(link.enable_collect),
        "passwordEnabled": bool(link.password_hash),
        "nonce": link.nonce,
        "memLimit": link.mem_limit,
        "opsLimit": link.ops_limit,
        "enableJoin": bool(link.enable_join),
    }


@public_router.post("/collections", response_model=PublicLinkResponse)
def create_public_collection_link(
    payload: PublicCollectionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    col = db.get(Collection, payload.collection_id)
    if not col or col.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Collection not found")
    token = _tok()
    link = PublicCollectionLink(
        token=token,
        collection_id=col.id,
        allow_upload=payload.allow_upload,
        password_hash=payload.password or None,
        expires_at=(
            dt.datetime.utcnow() + dt.timedelta(seconds=payload.expires_in_seconds)
            if payload.expires_in_seconds
            else None
        ),
    )
    db.add(link)
    db.commit()
    return PublicLinkResponse(token=token, url=f"/albums/collection/{token}")


@public_router.get("/collections/{token}")
def public_collection_redirect(token: str):
    base_url = (settings.albums_base_url or "").rstrip("/")
    target = f"{base_url}/{token}" if base_url else f"/albums/collection/{token}"
    return RedirectResponse(url=target, status_code=307)


@public_router.get("/collections/{token}/preview/{file_id}")
def public_preview(
    token: str,
    file_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    link = _validate_collection_token(db, token)
    _require_public_link_jwt(link, request)
    file = db.get(File, file_id)
    if not file or file.collection_id != link.collection_id:
        raise HTTPException(status_code=404, detail="Not found")
    redirect_url = _absolute_presign(
        presign_get(file.thumbnail_object_key or file.file_object_key),
        request,
    )
    return RedirectResponse(url=redirect_url, status_code=307)


@public_router.get("/files/{token}")
def public_file_redirect(token: str, request: Request, db: Session = Depends(get_db)):
    link = (
        db.query(PublicFileLink)
        .filter(PublicFileLink.token == token)
        .one_or_none()
    )
    if not link:
        raise HTTPException(status_code=404, detail="Invalid link")
    file = db.get(File, link.file_id)
    if not file:
        raise HTTPException(status_code=404, detail="Not found")
    redirect_url = _absolute_presign(presign_get(file.file_object_key), request)
    return RedirectResponse(url=redirect_url, status_code=307)


@public_router.post("/collections/{token}/commit-file")
def public_collection_commit_file(
    token: str,
    payload: FileCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    link = _validate_collection_token(db, token)
    _require_public_link_jwt(link, request)
    if not link.allow_upload:
        raise HTTPException(status_code=403, detail="Uploads disabled")
    size, _ = head_object_size_and_etag(payload.file.object_key)
    if size is None:
        raise HTTPException(status_code=400, detail="Object not found or inaccessible in S3")
    thumbnail_object_key = payload.thumbnail.object_key if payload.thumbnail else None
    thumbnail_size = None
    if thumbnail_object_key:
        try:
            thumbnail_size, _ = head_object_size_and_etag(thumbnail_object_key)
        except Exception:
            thumbnail_size = None
    magic_md = payload.magic_metadata
    pub_md = payload.pub_magic_metadata
    magic_header = magic_md.header if magic_md else (pub_md.header if pub_md else None)
    magic_data = magic_md.data if magic_md else (pub_md.data if pub_md else None)
    magic_version = magic_md.version if magic_md else (pub_md.version if pub_md else None)
    magic_count = magic_md.count if magic_md else (pub_md.count if pub_md else None)
    pub_header = pub_md.header if pub_md else None
    pub_data = pub_md.data if pub_md else None
    pub_version = pub_md.version if pub_md else None
    pub_count = pub_md.count if pub_md else None
    collection = db.get(Collection, link.collection_id)
    file = File(
        owner_id=collection.owner_id,
        collection_id=link.collection_id,
        file_object_key=payload.file.object_key,
        thumbnail_object_key=thumbnail_object_key,
        thumbnail_size=thumbnail_size,
        encrypted_key=payload.encrypted_key,
        key_decryption_nonce=payload.key_decryption_nonce,
        metadata_header=payload.metadata.decryption_header if payload.metadata else None,
        metadata_encrypted_data=payload.metadata.encrypted_data if payload.metadata else None,
        magic_metadata_header=magic_header,
        magic_metadata_data=magic_data,
        magic_metadata_version=magic_version,
        magic_metadata_count=magic_count,
        pub_magic_metadata_header=pub_header,
        pub_magic_metadata_data=pub_data,
        pub_magic_metadata_version=pub_version,
        pub_magic_metadata_count=pub_count,
        mime_type=payload.mime_type,
        original_filename=payload.original_filename,
        size=size,
        sha256=payload.sha256,
    )
    db.add(file)
    db.commit()
    db.refresh(file)
    return {"fileId": file.id}


@file_link_router.get("/info")
def file_link_info(
    request: Request,
    db: Session = Depends(get_db),
):
    link = _file_link_entry(db, request)
    file = db.get(File, link.file_id)
    if not file or file.owner_id != link.owner_id:
        raise HTTPException(status_code=404, detail="File not found")
    payload = _file_link_payload(db, link, file)
    return {"file": payload}


@file_link_router.get("/pass-info")
def file_link_pass_info(
    request: Request,
    db: Session = Depends(get_db),
):
    link = _file_link_entry(db, request, allow_password_bypass=True)
    if not link.pass_hash:
        raise HTTPException(status_code=400, detail="Password not configured for this link")
    return {
        "nonce": link.nonce,
        "opsLimit": link.ops_limit,
        "memLimit": link.mem_limit,
    }


@file_link_router.post("/verify-password")
def file_link_verify_password(
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
):
    link = _file_link_entry(db, request, allow_password_bypass=True)
    expected_hash = link.pass_hash
    provided_hash = payload.get("passHash")
    if not expected_hash:
        raise HTTPException(status_code=400, detail="Password not configured for this link")
    if not provided_hash or provided_hash != expected_hash:
        raise HTTPException(status_code=403, detail="Invalid password")
    jwt_token = _issue_public_access_jwt(provided_hash)
    return {"jwtToken": jwt_token}


@file_link_router.get("/thumbnail")
def file_link_thumbnail(
    request: Request,
    db: Session = Depends(get_db),
):
    link = _file_link_entry(db, request)
    file = db.get(File, link.file_id)
    if not file or file.owner_id != link.owner_id:
        raise HTTPException(status_code=404, detail="File not found")
    object_key = file.thumbnail_object_key or file.file_object_key
    if not object_key:
        raise HTTPException(status_code=404, detail="Thumbnail not available")
    redirect_url = _absolute_presign(presign_get(object_key), request)
    return RedirectResponse(url=redirect_url, status_code=307)


@file_link_router.get("/file")
def file_link_file(
    request: Request,
    db: Session = Depends(get_db),
):
    link = _file_link_entry(db, request)
    if not link.enable_download:
        raise HTTPException(status_code=403, detail="Downloads disabled for this link")
    file = db.get(File, link.file_id)
    if not file or file.owner_id != link.owner_id:
        raise HTTPException(status_code=404, detail="File not found")
    if not file.file_object_key:
        raise HTTPException(status_code=404, detail="File object missing")
    redirect_url = _absolute_presign(presign_get(file.file_object_key), request)
    return RedirectResponse(url=redirect_url, status_code=307)


@public_collection_router.post("/verify-password")
def verify_public_collection_password(
    request: Request,
    payload: dict,
    db: Session = Depends(get_db),
):
    link = _link_from_headers(db, request, require_jwt=False)
    expected_hash = link.password_hash
    provided_hash = payload.get("passHash")
    if not expected_hash:
        raise HTTPException(status_code=400, detail="Password not configured for this collection")
    if not provided_hash or provided_hash != expected_hash:
        raise HTTPException(status_code=403, detail="Invalid password")
    jwt_token = _issue_public_access_jwt(provided_hash)
    return {"jwtToken": jwt_token}


@public_collection_router.get("/info")
def public_collection_info(
    request: Request,
    db: Session = Depends(get_db),
):
    link = _link_from_headers(db, request, require_jwt=False)
    collection = db.get(Collection, link.collection_id)
    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")
    owner = db.get(User, collection.owner_id)
    collection_payload = {
        "id": collection.id,
        "owner": {"id": owner.id if owner else None, "email": owner.email if owner else ""},
        "encryptedKey": collection.encrypted_key or "",
        "keyDecryptionNonce": collection.key_decryption_nonce,
        "type": collection.collection_type or "album",
        "sharees": [],
        "publicURLs": [_public_url_payload(link, request)],
        "updationTime": _now_us(),
    }
    referral_code = getattr(collection, "referral_code", None)
    response = {"collection": collection_payload}
    if referral_code:
        response["referralCode"] = referral_code
    return response


@public_collection_router.get("/diff")
def public_collection_diff(
    request: Request,
    sinceTime: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    link = _link_from_headers(db, request)
    since_dt = dt.datetime.utcfromtimestamp(sinceTime / 1_000_000) if sinceTime else dt.datetime.utcfromtimestamp(0)
    files = (
        db.query(File)
        .filter(File.collection_id == link.collection_id, File.updated_at >= since_dt)
        .all()
    )
    diff = [
        {
            "id": file.id,
            "collectionID": file.collection_id,
            "ownerID": file.owner_id,
            "isDeleted": bool(file.is_trashed),
            "updatedAt": int((file.updated_at or file.created_at).timestamp() * 1_000_000),
        }
        for file in files
    ]
    return {"diff": diff, "hasMore": False}


@public_collection_router.get("/files/preview/{file_id}")
def public_collection_preview(
    file_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    link = _link_from_headers(db, request)
    file = _file_for_public_collection(db, link, file_id)
    object_key = file.thumbnail_object_key or file.file_object_key
    if not object_key:
        raise HTTPException(status_code=404, detail="Thumbnail not available")
    redirect_url = _absolute_presign(presign_get(object_key), request)
    return RedirectResponse(url=redirect_url, status_code=307)


@public_collection_router.get("/files/download/{file_id}")
def public_collection_download(
    file_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    link = _link_from_headers(db, request)
    if not link.enable_download:
        raise HTTPException(status_code=403, detail="Downloads disabled for this collection")
    file = _file_for_public_collection(db, link, file_id)
    if not file.file_object_key:
        raise HTTPException(status_code=404, detail="File object missing")
    redirect_url = _absolute_presign(presign_get(file.file_object_key), request)
    return RedirectResponse(url=redirect_url, status_code=307)


@public_collection_router.get("/upload-urls")
def public_collection_upload_urls(
    request: Request,
    count: int = Query(1, ge=1, le=50),
    db: Session = Depends(get_db),
):
    link = _link_from_headers(db, request)
    if not link.allow_upload:
        raise HTTPException(status_code=403, detail="Uploads disabled")
    urls: list[UploadURL] = []
    for _ in range(count):
        key = f"public/{link.token}/{uuid.uuid4().hex}"
        upload_url = _absolute_presign(presign_put(key), request)
        urls.append(UploadURL(objectKey=key, url=upload_url))
    return {"urls": [item.model_dump(by_alias=True) for item in urls]}


@public_collection_router.get("/multipart-upload-urls")
def public_collection_multipart_upload_urls(
    request: Request,
    count: int = Query(1, ge=1, le=20),
    parts: int = Query(4, ge=1, le=100),
    db: Session = Depends(get_db),
):
    link = _link_from_headers(db, request)
    if not link.allow_upload:
        raise HTTPException(status_code=403, detail="Uploads disabled")
    urls: list[MultipartUploadURLs] = []
    for _ in range(count):
        object_key = f"public/{link.token}/{uuid.uuid4().hex}"
        upload_id = mpu_init(object_key)
        part_urls = [
            _absolute_presign(mpu_presign_part(object_key, upload_id, idx), request)
            for idx in range(1, parts + 1)
        ]
        complete_url = _absolute_presign(
            f"/public-collection/multipart-complete?objectKey={object_key}&uploadId={upload_id}",
            request,
        )
        urls.append(
            MultipartUploadURLs(
                objectKey=object_key,
                uploadId=upload_id,
                partUrls=part_urls,
                completeUrl=complete_url,
            )
    )
    return {"urls": [item.model_dump(by_alias=True) for item in urls]}


@public_collection_router.post("/multipart-complete")
def public_collection_multipart_complete(
    request: Request,
    payload: MultipartCompleteRequest,
    db: Session = Depends(get_db),
):
    link = _link_from_headers(db, request)
    if not link.allow_upload:
        raise HTTPException(status_code=403, detail="Uploads disabled")
    parts = [
        {"PartNumber": part.part_number, "ETag": part.e_tag}
        for part in payload.parts
    ]
    result = mpu_complete(payload.object_key, payload.upload_id, parts)
    return {"completed": True, "result": result}


@public_collection_router.post("/file")
def public_collection_create_file(
    request: Request,
    payload: FileCreate,
    db: Session = Depends(get_db),
):
    link = _link_from_headers(db, request)
    if not link.allow_upload:
        raise HTTPException(status_code=403, detail="Uploads disabled")
    size, _ = head_object_size_and_etag(payload.file.object_key)
    if size is None:
        raise HTTPException(status_code=400, detail="Object not found or inaccessible in S3")
    thumbnail_object_key = payload.thumbnail.object_key if payload.thumbnail else None
    thumbnail_size = None
    if thumbnail_object_key:
        try:
            thumbnail_size, _ = head_object_size_and_etag(thumbnail_object_key)
        except Exception:
            thumbnail_size = None
    magic_md = payload.magic_metadata
    pub_md = payload.pub_magic_metadata

    magic_header = magic_md.header if magic_md else (pub_md.header if pub_md else None)
    magic_data = magic_md.data if magic_md else (pub_md.data if pub_md else None)
    magic_version = magic_md.version if magic_md else (pub_md.version if pub_md else None)
    magic_count = magic_md.count if magic_md else (pub_md.count if pub_md else None)

    pub_header = pub_md.header if pub_md else None
    pub_data = pub_md.data if pub_md else None
    pub_version = pub_md.version if pub_md else None
    pub_count = pub_md.count if pub_md else None

    collection = db.get(Collection, link.collection_id)
    file = File(
        owner_id=collection.owner_id,
        collection_id=link.collection_id,
        file_object_key=payload.file.object_key,
        thumbnail_object_key=thumbnail_object_key,
        thumbnail_size=thumbnail_size,
        encrypted_key=payload.encrypted_key,
        key_decryption_nonce=payload.key_decryption_nonce,
        metadata_header=payload.metadata.decryption_header if payload.metadata else None,
        metadata_encrypted_data=payload.metadata.encrypted_data if payload.metadata else None,
        magic_metadata_header=magic_header,
        magic_metadata_data=magic_data,
        magic_metadata_version=magic_version,
        magic_metadata_count=magic_count,
        mime_type=payload.mime_type,
        original_filename=payload.original_filename,
        size=size,
        sha256=payload.sha256,
        pub_magic_metadata_header=pub_header,
        pub_magic_metadata_data=pub_data,
        pub_magic_metadata_version=pub_version,
        pub_magic_metadata_count=pub_count,
    )
    db.add(file)
    db.commit()
    db.refresh(file)
    return {"fileId": file.id}


@public_collection_router.get("/files/data/fetch")
def public_collection_file_data_fetch(
    request: Request,
    fileID: int = Query(...),
    type: FileDataType = Query(...),
    preferNoContent: bool = Query(False),
    db: Session = Depends(get_db),
):
    link = _link_from_headers(db, request)
    entry = (
        db.query(FileDataEntry)
        .filter(
            FileDataEntry.file_id == fileID,
            FileDataEntry.data_type == type.value,
        )
        .one_or_none()
    )
    if not entry:
        if preferNoContent:
            return {}
        raise HTTPException(status_code=404, detail="Data not found")
    file = db.get(File, entry.file_id)
    if not file or file.collection_id != link.collection_id:
        raise HTTPException(status_code=404, detail="Data not found")
    item = FileDataItem(
        file_id=entry.file_id,
        type=type,
        encrypted_data=entry.encrypted_data or "",
        decryption_header=entry.decryption_header or "",
        updated_at=entry.updated_at_us,
    )
    return {"data": item.model_dump(by_alias=True)}


@public_collection_router.get("/files/data/preview")
def public_collection_file_preview(
    request: Request,
    fileID: int = Query(...),
    type: FileDataType = Query(FileDataType.VID_PREVIEW),
    db: Session = Depends(get_db),
):
    link = _link_from_headers(db, request)
    entry = (
        db.query(FileDataEntry)
        .filter(
            FileDataEntry.file_id == fileID,
            FileDataEntry.data_type == type.value,
        )
        .one_or_none()
    )
    if not entry or not entry.object_id:
        raise HTTPException(status_code=404, detail="Preview not found")
    file = db.get(File, entry.file_id)
    if not file or file.collection_id != link.collection_id:
        raise HTTPException(status_code=404, detail="Preview not found")
    url = _absolute_presign(presign_get(entry.object_id), request)
    return {"url": url}


__all__ = ["public_router", "public_collection_router"]
