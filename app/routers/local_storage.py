from __future__ import annotations

from typing import Dict

from botocore.exceptions import ClientError
from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse

from ..local_s3 import LocalS3Error
from ..s3 import get_local_client


router = APIRouter(prefix="/local-storage", tags=["local-storage"])


def _require_client(tier: str):
    client = get_local_client(tier)
    if not client:
        raise HTTPException(status_code=404, detail="Unknown storage tier")
    return client


def _verify(client, method: str, key: str, expires: int, signature: str, extra: Dict[str, str] | None = None) -> None:
    try:
        client.verify_signature(method, key, expires, signature, extra)
    except LocalS3Error as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


async def _async_body_chunks(request: Request):
    async for chunk in request.stream():
        if chunk:
            yield chunk


@router.put("/{tier}/{object_path:path}")
async def upload_object(
    tier: str,
    object_path: str,
    request: Request,
    expires: int = Query(...),
    signature: str = Query(...),
    upload_id: str | None = Query(None, alias="uploadId"),
    part_number: int | None = Query(None, alias="partNumber"),
):
    client = _require_client(tier)
    extra: Dict[str, str] = {}
    if upload_id:
        extra["uploadId"] = upload_id
    if part_number is not None:
        if not upload_id:
            raise HTTPException(status_code=400, detail="partNumber requires uploadId")
        extra["partNumber"] = str(part_number)
    elif upload_id:
        raise HTTPException(status_code=400, detail="uploadId requires partNumber")

    _verify(client, "PUT", object_path, expires, signature, extra)

    try:
        if upload_id:
            etag = await client.store_multipart_part_async(upload_id, int(part_number), _async_body_chunks(request))
        else:
            etag = await client.save_object_async(object_path, _async_body_chunks(request))
    except LocalS3Error as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    headers = {"ETag": f'"{etag}"'}
    return Response(status_code=200, headers=headers)


def _set_common_headers(response: Response, info: Dict[str, object], content_disposition: str | None) -> None:
    response.headers["Content-Length"] = str(info.get("ContentLength", ""))
    response.headers["ETag"] = f'"{info.get("ETag")}"'
    if "LastModified" in info and info["LastModified"]:
        response.headers["Last-Modified"] = str(info["LastModified"])
    if content_disposition:
        response.headers["Content-Disposition"] = content_disposition


def _stream_file(client, key: str):
    with client.open_for_read(key) as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            yield chunk


@router.get("/{tier}/{object_path:path}")
async def download_object(
    tier: str,
    object_path: str,
    expires: int = Query(...),
    signature: str = Query(...),
    response_disposition: str | None = Query(None, alias="response-content-disposition"),
):
    client = _require_client(tier)
    extra: Dict[str, str] = {}
    if response_disposition:
        extra["response-content-disposition"] = response_disposition
    _verify(client, "GET", object_path, expires, signature, extra)

    try:
        info = client.head_object(Bucket=None, Key=object_path)
    except ClientError as exc:
        raise HTTPException(status_code=404, detail="Object not found") from exc

    response = StreamingResponse(
        _stream_file(client, object_path),
        media_type=info.get("ContentType") or "application/octet-stream",
    )
    _set_common_headers(response, info, response_disposition)
    return response


@router.head("/{tier}/{object_path:path}")
async def head_object(
    tier: str,
    object_path: str,
    expires: int = Query(...),
    signature: str = Query(...),
    response_disposition: str | None = Query(None, alias="response-content-disposition"),
):
    client = _require_client(tier)
    extra: Dict[str, str] = {}
    if response_disposition:
        extra["response-content-disposition"] = response_disposition
    _verify(client, "HEAD", object_path, expires, signature, extra)

    try:
        info = client.head_object(Bucket=None, Key=object_path)
    except ClientError as exc:
        raise HTTPException(status_code=404, detail="Object not found") from exc

    response = Response(status_code=200)
    response.headers["Content-Type"] = info.get("ContentType", "application/octet-stream")
    _set_common_headers(response, info, response_disposition)
    return response
