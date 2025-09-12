
from __future__ import annotations
import datetime as dt
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import File, User
from ..schemas import TrashDiffResponse, TrashDiffItem, DeleteTrashFilesRequest, EmptyTrashRequest, DeleteResponse
from ..security import get_current_user
from ..s3 import delete_object

router = APIRouter(prefix="/trash", tags=["trash"])

@router.get("/v2/diff", response_model=TrashDiffResponse)
def trash_diff_v2(since_time: Optional[str] = Query(default=None, alias="sinceTime"), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    q = db.query(File).filter(File.owner_id == current_user.id)
    items = []
    if since_time:
        try:
            norm = since_time.replace("Z", "+00:00")
            since_dt = dt.datetime.fromisoformat(norm)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid sinceTime format. Use ISO 8601.")
        q = q.filter(File.trashed_at.isnot(None)).filter(File.trashed_at > since_dt)
    for f in q.all():
        if f.is_trashed or since_time:
            items.append(TrashDiffItem(fileId=f.id, trashedAt=f.trashed_at, isTrashed=f.is_trashed))
    return TrashDiffResponse(items=items)

@router.post("/delete", response_model=DeleteResponse)
def trash_delete(payload: DeleteTrashFilesRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    deleted = 0
    for fid in payload.file_ids:
        f = db.get(File, fid)
        if f and f.owner_id == current_user.id and f.is_trashed:
            for key in [f.file_object_key, f.thumbnail_object_key]:
                if key:
                    try: delete_object(key)
                    except Exception: pass
            db.delete(f); deleted += 1
    db.commit()
    return DeleteResponse(deleted=deleted)

@router.post("/empty", response_model=DeleteResponse)
def trash_empty(payload: EmptyTrashRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not payload.confirm:
        return DeleteResponse(deleted=0)
    q = db.query(File).filter(File.owner_id == current_user.id, File.is_trashed == True).all()
    deleted = 0
    for f in q:
        for key in [f.file_object_key, f.thumbnail_object_key]:
            if key:
                try: delete_object(key)
                except Exception: pass
        db.delete(f); deleted += 1
    db.commit()
    return DeleteResponse(deleted=deleted)
