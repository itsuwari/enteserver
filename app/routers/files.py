
from __future__ import annotations
import uuid, mimetypes, datetime as dt, secrets
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import File, Collection, User, FileShareLink, FileDataEntry
from ..schemas import (
    UploadURL, UploadURLResponse, MultipartUploadURLs, MultipartUploadURLsResponse,
    UploadURLV2Request, MultipartUploadURLV2Request,
    FileCreate, FileUpdate, FileIDsRequest, SizeResponse, FileInfoItem, FilesInfoResponse,
    UpdateThumbnailRequest, UpdateMultipleMagicMetadataRequest, PreviewURLResponse, TrashRequest,
    MultipartCompleteRequest, DuplicatesResponse,
    FileShareCreateRequest, FileShareUpdateRequest, FileShareResponse,
    MetaFileCreate, FileCopyRequest, FileCopyResponse,
    FileDataType, FileDataPutRequest, FileDataFetchRequest, FileDataFetchResponse,
    FileDataItem, FileDataDiffRequest, FileDataDiffResponse, FileDataDiffItem, FilePreviewResponse,
    VideoDataRequest
)
from ..security import get_current_user
from ..config import get_settings
from ..s3 import (
    presign_put,
    presign_get,
    mpu_init,
    mpu_presign_part,
    mpu_complete,
    head_object_size_and_etag,
    replicate_after_upload,
    object_storage_available,
    resolve_presigned_url,
)
from ..storage import enforce_storage_quota, add_file_to_storage_usage, remove_file_from_storage_usage, StorageQuotaExceeded

router = APIRouter(prefix="/files", tags=["files"])

# Use the new multi-cloud aware function
_head_size_and_etag = head_object_size_and_etag


def _absolute_presign(url: str, request: Request) -> str:
    return resolve_presigned_url(url, str(request.base_url))

def _dt_to_microseconds(value: dt.datetime | None) -> int:
    if not value:
        return 0
    if value.tzinfo is not None:
        value = value.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return int(value.timestamp() * 1_000_000)

def _microseconds_to_dt(value: int | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.utcfromtimestamp(value / 1_000_000)
    except Exception:
        raise HTTPException(status_code=400, detail="validTill must be microseconds since epoch")


def _microseconds_now() -> int:
    return int(dt.datetime.now(dt.timezone.utc).timestamp() * 1_000_000)


def _file_data_item_from_entry(entry: FileDataEntry) -> FileDataItem:
    return FileDataItem(
        file_id=entry.file_id,
        type=FileDataType(entry.data_type),
        encrypted_data=entry.encrypted_data or "",
        decryption_header=entry.decryption_header or "",
        updated_at=entry.updated_at_us,
    )

def _render_share_template(template: str, token: str) -> str:
    if "{token}" in template:
        return template.format(token=token)
    if template.endswith("/"):
        return template + token
    if template.endswith("="):
        return template + token
    return f"{template.rstrip('/')}/{token}"


def _share_url_for_link(link: FileShareLink, app_name: str | None = None) -> str:
    selected_app = (app_name or link.app or "photos").lower()
    cfg = get_settings()
    template = cfg.file_share_urls.get(selected_app) if hasattr(cfg, "file_share_urls") else None
    if template is None:
        template = cfg.file_share_url_template
    if template:
        try:
            return _render_share_template(template, link.token)
        except Exception:
            # Fall back to relative path if template formatting fails
            return f"/public/files/{link.token}"
    return f"/public/files/{link.token}"


def _share_link_to_response(link: FileShareLink, app_name: str | None = None) -> FileShareResponse:
    share_url = _share_url_for_link(link, app_name)
    return FileShareResponse(
        link_id=link.link_id,
        url=share_url,
        owner_id=link.owner_id,
        file_id=link.file_id,
        valid_till=_dt_to_microseconds(link.valid_till),
        device_limit=link.device_limit or 0,
        password_enabled=bool(link.pass_hash),
        nonce=link.nonce,
        mem_limit=link.mem_limit,
        ops_limit=link.ops_limit,
        enable_download=link.enable_download,
        created_at=_dt_to_microseconds(link.created_at),
    )

@router.get("/upload-urls", response_model=UploadURLResponse)
def get_upload_urls(
    request: Request,
    count: int = Query(1, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    urls = []
    for _ in range(count):
        key = f"{current_user.id}/" + uuid.uuid4().hex
        upload_url = _absolute_presign(presign_put(key), request)
        urls.append(UploadURL(objectKey=key, url=upload_url))
    return UploadURLResponse(urls=urls)

@router.get("/data/preview-upload-url", response_model=UploadURL)
def preview_upload_url(request: Request, current_user: User = Depends(get_current_user)):
    key = f"{current_user.id}/" + uuid.uuid4().hex
    return UploadURL(objectKey=key, url=_absolute_presign(presign_put(key), request))


@router.post("/meta")
def create_meta_file(
    payload: MetaFileCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not payload.metadata or not payload.metadata.encrypted_data:
        raise HTTPException(status_code=400, detail="metadata is required")

    collection = db.get(Collection, payload.collection_id)
    if not collection or collection.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Collection not found")

    file = File(
        owner_id=current_user.id,
        collection_id=payload.collection_id,
        file_object_key=f"meta/{current_user.id}/{uuid.uuid4().hex}",
        thumbnail_object_key=None,
        encrypted_key=payload.encrypted_key,
        key_decryption_nonce=payload.key_decryption_nonce,
        metadata_header=payload.metadata.decryption_header,
        metadata_encrypted_data=payload.metadata.encrypted_data,
        magic_metadata_header=payload.magic_metadata.header if payload.magic_metadata else None,
        magic_metadata_data=payload.magic_metadata.data if payload.magic_metadata else None,
        magic_metadata_version=payload.magic_metadata.version if payload.magic_metadata else None,
        pub_magic_metadata_header=payload.pub_magic_metadata.header if payload.pub_magic_metadata else None,
        pub_magic_metadata_data=payload.pub_magic_metadata.data if payload.pub_magic_metadata else None,
        pub_magic_metadata_version=payload.pub_magic_metadata.version if payload.pub_magic_metadata else None,
        pub_magic_metadata_count=payload.pub_magic_metadata.count if payload.pub_magic_metadata else None,
        mime_type="application/json",
        size=0,
        sha256=None,
        original_filename=None,
    )
    db.add(file)
    db.commit()
    db.refresh(file)
    updation_time = _microseconds_now()
    return {
        "id": file.id,
        "ownerID": file.owner_id,
        "collectionID": file.collection_id,
        "updationTime": updation_time,
    }


@router.post("/copy", response_model=FileCopyResponse)
def copy_files(
    payload: FileCopyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not payload.files:
        raise HTTPException(status_code=400, detail="files must contain at least one entry")

    dst_collection = db.get(Collection, payload.dst_collection_id)
    if not dst_collection or dst_collection.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Destination collection not found")

    result_map: dict[str, int] = {}
    for file_item in payload.files:
        original = db.get(File, file_item.id)
        if not original or original.owner_id != current_user.id:
            raise HTTPException(status_code=404, detail=f"File {file_item.id} not found")

        new_file = File(
            owner_id=current_user.id,
            collection_id=payload.dst_collection_id,
            file_object_key=original.file_object_key,
            thumbnail_object_key=original.thumbnail_object_key,
            encrypted_key=file_item.encrypted_key,
            key_decryption_nonce=file_item.key_decryption_nonce,
            metadata_header=original.metadata_header,
            metadata_encrypted_data=original.metadata_encrypted_data,
            magic_metadata_header=original.magic_metadata_header,
            magic_metadata_data=original.magic_metadata_data,
            magic_metadata_version=original.magic_metadata_version,
            pub_magic_metadata_header=original.pub_magic_metadata_header,
            pub_magic_metadata_data=original.pub_magic_metadata_data,
            pub_magic_metadata_version=original.pub_magic_metadata_version,
            pub_magic_metadata_count=original.pub_magic_metadata_count,
            mime_type=original.mime_type,
            size=original.size,
            sha256=original.sha256,
            original_filename=original.original_filename,
        )
        db.add(new_file)
        db.flush()
        result_map[str(original.id)] = new_file.id

    db.commit()
    return FileCopyResponse(old_to_new_file_id_map=result_map)


@router.put("/data")
def put_file_data(
    payload: FileDataPutRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if payload.type != FileDataType.ML_DATA:
        raise HTTPException(status_code=400, detail="Only mldata type is supported")
    if not payload.encrypted_data or not payload.decryption_header:
        raise HTTPException(status_code=400, detail="encryptedData and decryptionHeader are required")

    file = db.get(File, payload.file_id)
    if not file or file.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="File not found")

    entry = (
        db.query(FileDataEntry)
        .filter(
            FileDataEntry.file_id == payload.file_id,
            FileDataEntry.data_type == payload.type.value,
        )
        .one_or_none()
    )
    now_us = _microseconds_now()
    if entry:
        if payload.last_updated_at and payload.last_updated_at > 0 and entry.updated_at_us != payload.last_updated_at:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="STALE_VERSION")
        entry.encrypted_data = payload.encrypted_data
        entry.decryption_header = payload.decryption_header
        entry.version = payload.version or (entry.version + 1 if entry.version else 1)
        entry.updated_at_us = now_us
        entry.is_deleted = False
        entry.owner_id = file.owner_id
    else:
        entry = FileDataEntry(
            file_id=file.id,
            owner_id=file.owner_id,
            data_type=payload.type.value,
            encrypted_data=payload.encrypted_data,
            decryption_header=payload.decryption_header,
            version=payload.version or 1,
            updated_at_us=now_us,
        )
        db.add(entry)

    db.commit()
    db.refresh(entry)
    return {
        "fileId": entry.file_id,
        "type": entry.data_type,
        "updatedAt": entry.updated_at_us,
        "version": entry.version,
    }


@router.post("/data/fetch", response_model=FileDataFetchResponse)
def fetch_files_data(
    payload: FileDataFetchRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not payload.file_ids:
        raise HTTPException(status_code=400, detail="fileIDs must contain at least one entry")
    if len(payload.file_ids) > 200:
        raise HTTPException(status_code=400, detail="fileIDs should be less than or equal to 200")

    entries = (
        db.query(FileDataEntry)
        .filter(
            FileDataEntry.owner_id == current_user.id,
            FileDataEntry.data_type == payload.type.value,
            FileDataEntry.file_id.in_(payload.file_ids),
            FileDataEntry.is_deleted == False,
        )
        .all()
    )
    items = [_file_data_item_from_entry(entry) for entry in entries]
    present_ids = {entry.file_id for entry in entries}
    pending = [fid for fid in payload.file_ids if fid not in present_ids]

    return FileDataFetchResponse(
        data=items,
        pending_index_file_ids=pending,
        err_file_ids=[],
    )


@router.get("/data/fetch")
def fetch_file_data_single(
    file_id: int = Query(..., alias="fileID"),
    type: FileDataType = Query(...),
    prefer_no_content: bool = Query(False, alias="preferNoContent"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    entry = (
        db.query(FileDataEntry)
        .filter(
            FileDataEntry.owner_id == current_user.id,
            FileDataEntry.file_id == file_id,
            FileDataEntry.data_type == type.value,
        )
        .one_or_none()
    )
    if not entry or entry.is_deleted:
        if prefer_no_content:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        raise HTTPException(status_code=404, detail="File data not found")

    item = _file_data_item_from_entry(entry)
    return {"data": item.model_dump(by_alias=True)}


@router.post("/data/status-diff", response_model=FileDataDiffResponse)
def file_data_status_diff(
    payload: FileDataDiffRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if payload.last_updated_at is None or payload.last_updated_at < 0:
        raise HTTPException(status_code=400, detail="lastUpdatedAt must be >= 0")

    entries = (
        db.query(FileDataEntry)
        .filter(
            FileDataEntry.owner_id == current_user.id,
            FileDataEntry.updated_at_us > payload.last_updated_at,
        )
        .all()
    )
    diff_items = [
        FileDataDiffItem(
            file_id=entry.file_id,
            type=FileDataType(entry.data_type),
            is_deleted=entry.is_deleted,
            object_id=entry.object_id,
            object_size=entry.object_size,
            updated_at=entry.updated_at_us,
        )
        for entry in entries
    ]
    return FileDataDiffResponse(diff=diff_items)


@router.get("/data/preview", response_model=FilePreviewResponse)
def fetch_file_preview_data(
    request: Request,
    file_id: int = Query(..., alias="fileID"),
    type: FileDataType = Query(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if type != FileDataType.VID_PREVIEW:
        raise HTTPException(status_code=400, detail="Only vid_preview type is supported")

    entry = (
        db.query(FileDataEntry)
        .filter(
            FileDataEntry.owner_id == current_user.id,
            FileDataEntry.file_id == file_id,
            FileDataEntry.data_type == type.value,
            FileDataEntry.is_deleted == False,
        )
        .one_or_none()
    )
    if not entry or not entry.object_id:
        raise HTTPException(status_code=404, detail="Preview not found")

    url = _absolute_presign(presign_get(entry.object_id), request)
    return FilePreviewResponse(url=url)


@router.put("/video-data")
def put_video_data(
    payload: VideoDataRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not payload.playlist or not payload.playlist_header:
        raise HTTPException(status_code=400, detail="playlist and playlistHeader are required")

    file = db.get(File, payload.file_id)
    if not file or file.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="File not found")

    entry = (
        db.query(FileDataEntry)
        .filter(
            FileDataEntry.file_id == payload.file_id,
            FileDataEntry.data_type == FileDataType.VID_PREVIEW.value,
        )
        .one_or_none()
    )
    now_us = _microseconds_now()
    if entry:
        entry.encrypted_data = payload.playlist
        entry.decryption_header = payload.playlist_header
        entry.object_id = payload.object_id
        entry.object_size = payload.object_size
        entry.version = payload.version or (entry.version + 1 if entry.version else 1)
        entry.updated_at_us = now_us
        entry.is_deleted = False
        entry.owner_id = file.owner_id
    else:
        entry = FileDataEntry(
            file_id=file.id,
            owner_id=file.owner_id,
            data_type=FileDataType.VID_PREVIEW.value,
            encrypted_data=payload.playlist,
            decryption_header=payload.playlist_header,
            object_id=payload.object_id,
            object_size=payload.object_size,
            version=payload.version or 1,
            updated_at_us=now_us,
        )
        db.add(entry)

    db.commit()
    return {
        "fileId": entry.file_id,
        "type": entry.data_type,
        "updatedAt": entry.updated_at_us,
        "version": entry.version,
    }

@router.post("/upload-url", response_model=UploadURL)
def create_upload_url(
    request: Request,
    payload: UploadURLV2Request,
    current_user: User = Depends(get_current_user),
):
    if payload.content_length <= 0:
        raise HTTPException(status_code=400, detail="contentLength must be greater than 0")
    key = f"{current_user.id}/" + uuid.uuid4().hex
    upload_url = _absolute_presign(
        presign_put(
            key,
            content_length=payload.content_length,
            content_md5=payload.content_md5,
        ),
        request,
    )
    return UploadURL(objectKey=key, url=upload_url)

@router.get("/multipart-upload-urls", response_model=MultipartUploadURLsResponse)
def multipart_upload_urls(
    request: Request,
    count: int = Query(1, ge=1, le=50),
    parts: int = Query(4, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    items = []
    for _ in range(count):
        object_key = f"{current_user.id}/" + uuid.uuid4().hex
        upload_id = mpu_init(object_key)
        part_urls = [
            _absolute_presign(mpu_presign_part(object_key, upload_id, n), request)
            for n in range(1, parts + 1)
        ]
        complete_url = _absolute_presign(
            f"/files/multipart-complete?objectKey={object_key}&uploadId={upload_id}",
            request,
        )
        items.append(MultipartUploadURLs(objectKey=object_key, uploadId=upload_id, partUrls=part_urls, completeUrl=complete_url))
    return MultipartUploadURLsResponse(urls=items)

@router.post("/multipart-upload-url", response_model=MultipartUploadURLs)
def multipart_upload_url(
    request: Request,
    payload: MultipartUploadURLV2Request,
    current_user: User = Depends(get_current_user),
):
    if payload.content_length <= 0 or payload.part_length <= 0:
        raise HTTPException(status_code=400, detail="contentLength and partLength must be greater than 0")
    if not payload.part_md5s:
        raise HTTPException(status_code=400, detail="partMd5s must contain at least one entry")
    object_key = f"{current_user.id}/" + uuid.uuid4().hex
    upload_id = mpu_init(object_key)
    part_urls = [
        _absolute_presign(mpu_presign_part(object_key, upload_id, idx + 1), request)
        for idx, _ in enumerate(payload.part_md5s)
    ]
    complete_url = _absolute_presign(
        f"/files/multipart-complete?objectKey={object_key}&uploadId={upload_id}",
        request,
    )
    return MultipartUploadURLs(objectKey=object_key, uploadId=upload_id, partUrls=part_urls, completeUrl=complete_url)

@router.post("/multipart-complete")
def multipart_complete(payload: MultipartCompleteRequest, current_user: User = Depends(get_current_user)):
    parts = [{"PartNumber": it.part_number, "ETag": it.e_tag} for it in sorted(payload.parts, key=lambda x: x.part_number)]
    
    # Complete multipart upload with automatic replication
    result = mpu_complete(
        payload.object_key,
        payload.upload_id,
        parts,
        subscription_type=current_user.subscription_type
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
        original_file=f,
        db=db
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
def download_file(file_id: int, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    f = db.get(File, file_id)
    if not f or f.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="File not found")
    if object_storage_available():
        redirect_url = _absolute_presign(
            presign_get(f.file_object_key, response_filename=f.original_filename or f"file_{f.id}"),
            request,
        )
        return RedirectResponse(url=redirect_url, status_code=307)
    raise HTTPException(status_code=501, detail="Object storage disabled")

@router.get("/preview/{file_id}", response_model=None)
def preview_file(file_id: int, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    f = db.get(File, file_id)
    if not f or f.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="File not found")
    if object_storage_available():
        redirect_url = _absolute_presign(
            presign_get(f.thumbnail_object_key or f.file_object_key),
            request,
        )
        return RedirectResponse(url=redirect_url, status_code=307)
    raise HTTPException(status_code=501, detail="Object storage disabled")

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
        raise HTTPException(status_code=400, detail="thumbnail object not found in object storage")
    f.thumbnail_object_key = payload.object_key
    db.commit()
    return {"fileId": f.id, "thumbnailObjectKey": f.thumbnail_object_key}

@router.post("/share-url", response_model=FileShareResponse)
def create_file_share_url(
    payload: FileShareCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    app_name = (payload.app or "").lower()
    if app_name not in ("photos", "locker"):
        raise HTTPException(status_code=400, detail="Unsupported app")
    file = db.get(File, payload.file_id)
    if not file or file.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="File not found")
    existing = (
        db.query(FileShareLink)
        .filter(
            FileShareLink.owner_id == current_user.id,
            FileShareLink.file_id == file.id,
            FileShareLink.app == app_name,
            FileShareLink.is_disabled == False,
        )
        .order_by(FileShareLink.created_at.desc())
        .first()
    )
    if existing:
        return _share_link_to_response(existing, app_name)
    link = FileShareLink(
        owner_id=current_user.id,
        file_id=file.id,
        link_id=uuid.uuid4().hex,
        token=secrets.token_urlsafe(16),
        app=app_name,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return _share_link_to_response(link, app_name)

@router.put("/share-url", response_model=FileShareResponse)
def update_file_share_url(
    payload: FileShareUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    link = (
        db.query(FileShareLink)
        .filter(
            FileShareLink.link_id == payload.link_id,
            FileShareLink.owner_id == current_user.id,
            FileShareLink.is_disabled == False,
        )
        .first()
    )
    if not link:
        raise HTTPException(status_code=404, detail="Share link not found")
    if link.file_id != payload.file_id:
        raise HTTPException(status_code=400, detail="fileID mismatch")
    if payload.valid_till is not None:
        link.valid_till = _microseconds_to_dt(payload.valid_till)
    if payload.device_limit is not None:
        if payload.device_limit < 0 or payload.device_limit > 50:
            raise HTTPException(status_code=400, detail="deviceLimit out of range")
        link.device_limit = payload.device_limit
    pass_fields = [payload.pass_hash, payload.nonce, payload.mem_limit, payload.ops_limit]
    if all(field is not None for field in pass_fields):
        link.pass_hash = payload.pass_hash
        link.nonce = payload.nonce
        link.mem_limit = payload.mem_limit
        link.ops_limit = payload.ops_limit
    elif payload.disable_password:
        link.pass_hash = None
        link.nonce = None
        link.mem_limit = None
        link.ops_limit = None
    elif any(field is not None for field in pass_fields):
        raise HTTPException(status_code=400, detail="All password fields must be provided together")
    if payload.enable_download is not None:
        link.enable_download = payload.enable_download
    db.commit()
    db.refresh(link)
    return _share_link_to_response(link, link.app)

@router.delete("/share-url/{file_id}")
def disable_file_share_url(
    file_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    links = (
        db.query(FileShareLink)
        .filter(
            FileShareLink.owner_id == current_user.id,
            FileShareLink.file_id == file_id,
            FileShareLink.is_disabled == False,
        )
        .all()
    )
    if not links:
        return {}
    for link in links:
        link.is_disabled = True
    db.commit()
    return {}

@router.get("/share-urls")
@router.get("/share-urls/")
def list_file_share_urls(
    since_time: int = Query(0, alias="sinceTime"),
    limit: int = Query(500, ge=1, le=500),
    app_filter: str | None = Query(None, alias="app"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = (
        db.query(FileShareLink)
        .filter(
            FileShareLink.owner_id == current_user.id,
            FileShareLink.is_disabled == False,
        )
        .order_by(FileShareLink.updated_at.desc())
    )
    if app_filter:
        query = query.filter(FileShareLink.app == app_filter.lower())
    if since_time:
        since_dt = _microseconds_to_dt(since_time)
        query = query.filter(FileShareLink.updated_at >= since_dt)
    links = query.limit(limit).all()
    responses = [_share_link_to_response(link, link.app).model_dump(by_alias=True) for link in links]
    next_since = since_time
    timestamps = [_dt_to_microseconds(link.updated_at) for link in links if link.updated_at]
    if timestamps:
        next_since = max(timestamps)
    return {"diff": responses, "nextSince": next_since}

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
