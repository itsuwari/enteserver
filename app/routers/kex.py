
from __future__ import annotations
import datetime as dt, secrets
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import KexRecord

router = APIRouter(prefix="/kex", tags=["kex"])

@router.put("/add")
def kex_add(wrappedKey: str, customIdentifier: str | None = Query(default=None), ttlSeconds: int = Query(86400), db: Session = Depends(get_db)):
    identifier = customIdentifier or secrets.token_urlsafe(10)
    if db.query(KexRecord).filter(KexRecord.identifier == identifier).first():
        raise HTTPException(status_code=409, detail="identifier exists")
    rec = KexRecord(identifier=identifier, wrapped_key=wrappedKey, expires_at=dt.datetime.utcnow() + dt.timedelta(seconds=ttlSeconds))
    db.add(rec); db.commit()
    return {"identifier": identifier}

@router.get("/get")
def kex_get(identifier: str, db: Session = Depends(get_db)):
    rec = db.query(KexRecord).filter(KexRecord.identifier == identifier).first()
    if not rec or (rec.expires_at and rec.expires_at < dt.datetime.utcnow()) or rec.consumed:
        raise HTTPException(status_code=404, detail="not found")
    rec.consumed = True; db.commit()
    return {"wrappedKey": rec.wrapped_key}
