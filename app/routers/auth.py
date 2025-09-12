
from __future__ import annotations
import datetime as dt, secrets
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from ..db import get_db
from ..schemas import LoginRequest, LoginResponse, SessionInfo, RevokeOthersResponse, DeleteResponse
from ..models import User, UserSession
from ..config import settings
from ..security import hash_password, verify_password, create_token, get_auth

router = APIRouter(prefix="/users", tags=["auth"])

def _bootstrap(db: Session):
    user = db.query(User).filter(User.email == settings.admin_email).first()
    if not user:
        u = User(email=settings.admin_email, password_hash=hash_password(settings.admin_password))
        db.add(u); db.commit()

@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    _bootstrap(db)
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    jti = secrets.token_urlsafe(12)
    ip = request.headers.get('X-Forwarded-For') or (request.client.host if request.client else None)
    ua = request.headers.get('User-Agent')
    cp = request.headers.get('X-Client-Package')
    cv = request.headers.get('X-Client-Version')
    sess = UserSession(user_id=user.id, jti=jti, ip=ip, user_agent=ua, client_package=cp, client_version=cv)
    db.add(sess); db.commit()
    exp_seconds = settings.jwt_exp_hours * 3600
    token = create_token(user.id, extra={"jti": jti})
    return LoginResponse(auth_token=token, expires_in=exp_seconds)

@router.get("/sessions")
def sessions(db: Session = Depends(get_db), ctx=Depends(get_auth)):
    user = ctx['user']
    rows = db.query(UserSession).filter(UserSession.user_id == user.id).order_by(UserSession.created_at.desc()).all()
    return [SessionInfo(id=s.id, createdAt=s.created_at, lastSeenAt=s.last_seen_at, ip=s.ip, userAgent=s.user_agent, clientPackage=s.client_package, clientVersion=s.client_version, active=not s.revoked) for s in rows]

@router.delete("/sessions/{session_id}", response_model=DeleteResponse)
def revoke_session(session_id: int, db: Session = Depends(get_db), ctx=Depends(get_auth)):
    user = ctx['user']
    s = db.query(UserSession).filter(UserSession.id == session_id, UserSession.user_id == user.id).first()
    if not s:
        return DeleteResponse(deleted=0)
    s.revoked = True; db.commit()
    return DeleteResponse(deleted=1)

@router.post("/sessions/revoke-others", response_model=RevokeOthersResponse)
def revoke_other_sessions(db: Session = Depends(get_db), ctx=Depends(get_auth)):
    user = ctx['user']; jti = ctx['jti']
    if not jti:
        q = db.query(UserSession).filter(UserSession.user_id == user.id, UserSession.revoked == False)
        count = q.count()
        for s in q: s.revoked = True
        db.commit()
        return RevokeOthersResponse(revoked=count)
    q = db.query(UserSession).filter(UserSession.user_id == user.id, UserSession.jti != jti, UserSession.revoked == False)
    count = q.count()
    for s in q: s.revoked = True
    db.commit()
    return RevokeOthersResponse(revoked=count)

@router.delete("/sessions/current", response_model=DeleteResponse)
def revoke_current_session(db: Session = Depends(get_db), ctx=Depends(get_auth)):
    user = ctx['user']; jti = ctx['jti']
    if not jti:
        return DeleteResponse(deleted=0)
    s = db.query(UserSession).filter(UserSession.user_id == user.id, UserSession.jti == jti).first()
    if not s or s.revoked:
        return DeleteResponse(deleted=0)
    s.revoked = True; db.commit()
    return DeleteResponse(deleted=1)


import base64, os, jwt

@router.get("/accounts-token")
def accounts_token(current = Depends(get_auth)):
    # get_auth returns { 'user': User, 'jti': str | None }
    user = current['user']
    if not settings.accounts_jwt_secret:
        raise HTTPException(status_code=501, detail="ACCOUNTS_JWT_SECRET not set")
    
    now = dt.datetime.utcnow()
    payload = {
        "iss": settings.accounts_jwt_iss,
        "aud": settings.accounts_jwt_aud,
        "sub": str(user.id),
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(seconds=settings.accounts_jwt_ttl_sec)).timestamp()),
    }
    token = jwt.encode(payload, settings.accounts_jwt_secret, algorithm="HS256")
    return {"accountsToken": base64.b64encode(token.encode("utf-8")).decode("ascii")}
