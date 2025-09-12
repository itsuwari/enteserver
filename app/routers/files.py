
from __future__ import annotations
import uuid, mimetypes, datetime as dt
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import File, User
from ..schemas import (
    UploadURL, UploadURLResponse, MultipartUploadURLs, MultipartUploadURLsResponse,
    FileCreate, FileUpdate, FileIDsRequest, SizeResponse, FileInfoItem, FilesInfoResponse,
    UpdateThumbnailRequest, UpdateMultipleMagicMetadataRequest, PreviewURLResponse, TrashRequest,
    MultipartCompleteRequest, DuplicatesResponse
)
from ..security import get_current_user
from ..config import settings
from ..s3 import presign_put, presign_get, mpu_init, mpu_presign_part, mpu_complete, head_object_size_and_etag, StorageTier, replicate_after_upload
from ..storage import enforce_storage_quota, add_file_to_storage_usage, remove_file_from_storage_usage, StorageQuotaExceeded
from ..schemas import StorageQuotaExceededError

router = APIRouter(prefix="/files", tags=["files"])

# Use the new multi-cloud aware function
_head_size_and_etag = head_object_size_and_etag

@router.get("/upload-urls", response_model=UploadURLResponse)
def get_upload_urls(count: int = Query(1, ge=1, le=100), current_user: User = Depends(get_current_user)):
    urls = []
    for _ in range(count):
        key = f"{current_user.id}/" + uuid.uuid4().hex
        urls.append(UploadURL(objectKey=key, url=presign_put(key)))
    return UploadURLResponse(urls=urls)

@router.get("/data/preview-upload-url", response_model=UploadURL)
def preview_upload_url(current_user: User = Depends(get_current_user)):
    key = f"{current_user.id}/" + uuid.uuid4().hex
    return UploadURL(objectKey=key, url=presign_put(key))

@router.get("/multipart-upload-urls", response_model=MultipartUploadURLsResponse)
def multipart_upload_urls(count: int = Query(1, ge=1, le=50), parts: int = Query(4, ge=1, le=100), current_user: User = Depends(get_current_user)):
    items = []
    for _ in range(count):
        object_key = f"{current_user.id}/" + uuid.uuid4().hex
        upload_id = mpu_init(object_key)
        part_urls = [mpu_presign_part(object_key, upload_id, n) for n in range(1, parts+1)]
        complete_url = f"/files/multipart-complete?objectKey={object_key}&uploadId={upload_id}"
        items.append(MultipartUploadURLs(objectKey=object_key, uploadId=upload_id, partUrls=part_urls, completeUrl=complete_url))
    return MultipartUploadURLsResponse(urls=items)

@router.post("/multipart-complete")
def multipart_complete(payload: MultipartCompleteRequest, current_user: User = Depends(get_current_user)):
    parts = [{"PartNumber": it.part_number, "ETag": it.e_tag} for it in sorted(payload.parts, key=lambda x: x.part_number)]
    
    # Complete multipart upload with automatic replication
    result = mpu_complete(
        payload.object_key, 
        payload.upload_id, 
        parts, 
        StorageTier.PRIMARY, 
        current_user.subscription_type
    )
    
    return {"completed": True, "result": result}

@router.post("")
def create_or_update_file(payload: FileCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    size, _ = _head_size_and_etag(payload.file.object_key)
    if size is None:
        raise HTTPException(status_code=400, detail="Object not found or inaccessible in S3")
    
    # Enforce storage quota before creating file
    try:
        enforce_storage_quota(current_user.id, size, db)
    except StorageQuotaExceeded as e:
        raise HTTPException(
            status_code=413,  # Payload Too Large
            detail={
                "error": "STORAGE_QUOTA_EXCEEDED",
                "message": f"Storage quota exceeded. Used: {e.used} bytes, Quota: {e.quota} bytes, Requested: {e.requested} bytes",
                "used": e.used,
                "quota": e.quota,
                "requested": e.requested,
                "available": e.quota - e.used
            }
        )
    
    mime_type = payload.mime_type or mimetypes.guess_type(payload.original_filename or "")[0]
    f = File(
        owner_id=current_user.id,
        collection_id=payload.collection_id,
        file_object_key=payload.file.object_key,
        thumbnail_object_key=payload.thumbnail.object_key if payload.thumbnail else None,
        encrypted_key=payload.encrypted_key,
        key_decryption_nonce=payload.key_decryption_nonce,
        metadata_header=payload.metadata.decryption_header if payload.metadata else None,
        metadata_encrypted_data=payload.metadata.encrypted_data if payload.metadata else None,
        magic_metadata_header=(payload.magic_metadata.header if payload.magic_metadata else (payload.pub_magic_metadata.header if payload.pub_magic_metadata else None)),
        magic_metadata_data=(payload.magic_metadata.data if payload.magic_metadata else (payload.pub_magic_metadata.data if payload.pub_magic_metadata else None)),
        mime_type=mime_type,
        original_filename=payload.original_filename,
        size=size,
        sha256=payload.sha256,
    )
    db.add(f); db.commit(); db.refresh(f)
    
    # Update user's storage usage
    add_file_to_storage_usage(current_user.id, size, db)
    
    # Automatically replicate to appropriate tiers based on subscription
    replication_results = replicate_after_upload(
        payload.file.object_key, 
        current_user.subscription_type, 
        StorageTier.PRIMARY,
        f,  # Pass the original file object
        db  # Pass the database session
    )
    
    response = {"fileId": f.id}
    if replication_results:
        response["replication"] = replication_results
    
    return response

@router.put("/update")
def update_file(payload: FileUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    f = db.get(File, payload.file_id)
    if not f or f.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="File not found")
    if payload.collection_id is not None:
        f.collection_id = payload.collection_id
    if payload.thumbnail:
        ts, _ = _head_size_and_etag(payload.thumbnail.object_key)
        if ts is None:
            raise HTTPException(status_code=400, detail="thumbnail object not found in S3")
        f.thumbnail_object_key = payload.thumbnail.object_key
    if payload.metadata:
        f.metadata_header = payload.metadata.decryption_header
        f.metadata_encrypted_data = payload.metadata.encrypted_data
    if payload.magic_metadata:
        f.magic_metadata_header = payload.magic_metadata.header
        f.magic_metadata_data = payload.magic_metadata.data
    if payload.original_filename is not None:
        f.original_filename = payload.original_filename
    if payload.mime_type is not None:
        f.mime_type = payload.mime_type
    db.commit()
    return {"fileId": f.id, "updated": True}

@router.get("/download/{file_id}")
def download_file(file_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    f = db.get(File, file_id)
    if not f or f.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="File not found")
    if settings.s3_enabled:
        return RedirectResponse(url=presign_get(f.file_object_key, response_filename=f.original_filename or f"file_{f.id}"), status_code=307)
    raise HTTPException(status_code=501, detail="Local storage disabled")

@router.get("/preview/{file_id}", response_model=None)
def preview_file(file_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    f = db.get(File, file_id)
    if not f or f.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="File not found")
    if settings.s3_enabled:
        return RedirectResponse(url=presign_get(f.thumbnail_object_key or f.file_object_key), status_code=307)
    raise HTTPException(status_code=501, detail="Local storage disabled")

@router.post("/size", response_model=SizeResponse)
def files_size(payload: FileIDsRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    total = 0
    for fid in payload.file_ids:
        f = db.get(File, fid)
        if f and f.owner_id == current_user.id and f.size:
            total += int(f.size)
    return SizeResponse(size=total)

@router.post("/info", response_model=FilesInfoResponse)
def files_info(payload: FileIDsRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    items = []
    for fid in payload.file_ids:
        f = db.get(File, fid)
        if f and f.owner_id == current_user.id:
            items.append(FileInfoItem(
                id=f.id, objectKey=f.file_object_key, size=f.size, sha256=f.sha256, createdAt=f.created_at,
                mimeType=f.mime_type, collectionID=f.collection_id, isTrashed=f.is_trashed
            ))
    return FilesInfoResponse(files=items)

@router.put("/thumbnail")
def update_thumbnail(payload: UpdateThumbnailRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    f = db.get(File, payload.file_id)
    if not f or f.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="File not found")
    ts, _ = _head_size_and_etag(payload.object_key)
    if ts is None:
        raise HTTPException(status_code=400, detail="thumbnail object not found in S3")
    f.thumbnail_object_key = payload.object_key
    db.commit()
    return {"fileId": f.id, "thumbnailObjectKey": f.thumbnail_object_key}

@router.put("/magic-metadata")
def update_magic_metadata(payload: UpdateMultipleMagicMetadataRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    updated = 0
    for item in payload.items:
        f = db.get(File, item.file_id)
        if f and f.owner_id == current_user.id:
            f.magic_metadata_header = item.magic_metadata.header
            f.magic_metadata_data = item.magic_metadata.data
            updated += 1
    db.commit()
    return {"updated": updated}

@router.get("/count")
def public_files_count(db: Session = Depends(get_db)):
    return {"count": db.query(File).count()}

@router.post("/trash")
def trash_files(payload: TrashRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    now = dt.datetime.utcnow()
    trashed = 0
    for item in payload.items:
        f = db.get(File, item.file_id)
        if f and f.owner_id == current_user.id and not f.is_trashed:
            f.is_trashed = True
            f.trashed_at = now
            trashed += 1
    db.commit()
    return {"trashed": trashed}

@router.post("/restore")
def restore_files(payload: FileIDsRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    restored = 0
    for fid in payload.file_ids:
        f = db.get(File, fid)
        if f and f.owner_id == current_user.id and f.is_trashed:
            f.is_trashed = False
            f.trashed_at = None
            restored += 1
    db.commit()
    return {"restored": restored}

@router.post("/delete")
def delete_files(payload: FileIDsRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from ..s3 import delete_object
    deleted = 0
    total_size_freed = 0
    
    for fid in payload.file_ids:
        f = db.get(File, fid)
        if f and f.owner_id == current_user.id:
            if not f.is_trashed:
                continue
            
            # Track file size for storage usage update
            file_size = f.size or 0
            
            # Delete from S3
            for key in [f.file_object_key, f.thumbnail_object_key]:
                if key:
                    try: delete_object(key)
                    except Exception: pass
            
            # Delete from database
            db.delete(f)
            deleted += 1
            total_size_freed += file_size
    
    db.commit()
    
    # Update user's storage usage
    if total_size_freed > 0:
        remove_file_from_storage_usage(current_user.id, total_size_freed, db)
    
    return {"deleted": deleted, "storage_freed": total_size_freed}

@router.get("/duplicates", response_model=DuplicatesResponse)
def files_duplicates(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from collections import defaultdict
    rows = db.query(File.id, File.sha256, File.size).filter(File.owner_id == current_user.id, File.sha256.isnot(None)).all()
    groups = defaultdict(list)
    for fid, sha, sz in rows:
        groups[sha].append((fid, sz))
    dups = []
    for sha, items in groups.items():
        if len(items) > 1:
            dups.append({"fileIds": [i[0] for i in items], "size": items[0][1], "sha256": sha})
    return {"duplicates": dups}
