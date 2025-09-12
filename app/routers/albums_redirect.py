
from __future__ import annotations
from fastapi import APIRouter
from fastapi.responses import RedirectResponse
from ..config import settings

router = APIRouter(prefix="/albums", tags=["albums-redirect"])

@router.get("/collection/{token}")
def redirect_collection(token: str):
    return RedirectResponse(url=f"{settings.albums_base_url.rstrip('/')}/{token}", status_code=307)

@router.get("/file/{token}")
def redirect_file(token: str):
    return RedirectResponse(url=f"{settings.albums_base_url.rstrip('/')}/{token}", status_code=307)
