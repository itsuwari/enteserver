
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import Collection, User
from ..schemas import CollectionCreate, CollectionResponse
from ..security import get_current_user

router = APIRouter(prefix="/collections", tags=["collections"])

@router.post("", response_model=CollectionResponse)
def create_collection(payload: CollectionCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    c = Collection(owner_id=current_user.id, name=payload.name)
    db.add(c); db.commit(); db.refresh(c)
    return CollectionResponse(id=c.id, name=c.name)

@router.get("", response_model=list[CollectionResponse])
def list_collections(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    rows = db.query(Collection).filter(Collection.owner_id == current_user.id).all()
    return [CollectionResponse(id=c.id, name=c.name) for c in rows]


from typing import Optional
from fastapi import Query
import datetime as dt

def _parse_since_time(since: Optional[str]) -> dt.datetime:
    if since is None or str(since).strip() == "":
        return dt.datetime.utcfromtimestamp(0)
    s = str(since).strip()
    if s.isdigit():
        # microseconds since epoch
        try:
            us = int(s)
            return dt.datetime.utcfromtimestamp(us / 1_000_000.0)
        except Exception:
            raise HTTPException(status_code=400, detail="sinceTime must be microseconds or ISO8601")
    # allow trailing Z
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dtobj = dt.datetime.fromisoformat(s)
        if dtobj.tzinfo is not None:
            dtobj = dtobj.astimezone(dt.timezone.utc).replace(tzinfo=None)
        return dtobj
    except Exception:
        raise HTTPException(status_code=400, detail="sinceTime must be microseconds or ISO8601")

@router.get("/v2")
def list_collections_delta(
    sinceTime: Optional[str] = Query(default=None, description="microseconds since epoch or ISO8601"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    since_dt = _parse_since_time(sinceTime)
    rows = db.query(Collection).filter(
        Collection.owner_id == current_user.id,
        Collection.updated_at >= since_dt
    ).all()
    # Build response compatible with clients expecting delta + cursors
    server_time_us = int(dt.datetime.utcnow().timestamp() * 1_000_000)
    next_since = server_time_us
    items = [{"id": c.id, "name": c.name, "updatedAtUs": int(c.updated_at.timestamp() * 1_000_000)} for c in rows]
    if items:
        next_since = max(next_since, max(i["updatedAtUs"] for i in items))
    return {"serverTime": server_time_us, "nextSince": next_since, "collections": items}
