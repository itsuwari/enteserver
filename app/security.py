
from __future__ import annotations
import datetime as dt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
import jwt
from sqlalchemy.orm import Session
from .db import get_db
from .config import settings
from .models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
auth_scheme = HTTPBearer(auto_error=False)

def hash_password(p: str) -> str:
    return pwd_context.hash(p)

def verify_password(p: str, h: str) -> bool:
    return pwd_context.verify(p, h)

def create_token(user_id: int, extra: dict | None = None) -> str:
    now = dt.datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "iss": settings.jwt_issuer,
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(hours=settings.jwt_exp_hours)).timestamp()),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")

def get_auth(request: Request, creds: HTTPAuthorizationCredentials = Depends(auth_scheme), db: Session = Depends(get_db)):
    token = None
    if creds and creds.scheme and creds.scheme.lower() == "bearer":
        token = creds.credentials
    if not token:
        token = request.headers.get("X-Auth-Token") or request.query_params.get("token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"], options={"verify_aud": False})
        user_id = int(payload.get("sub"))
        jti = payload.get("jti")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if jti:
        from .models import UserSession
        sess = db.query(UserSession).filter(UserSession.jti == jti, UserSession.user_id == user.id).first()
        if not sess or sess.revoked:
            raise HTTPException(status_code=401, detail="Session revoked or missing")
        try:
            sess.last_seen_at = dt.datetime.utcnow()
            db.commit()
        except Exception:
            db.rollback()
    return {"user": user, "jti": jti}

def get_current_user(request: Request, creds: HTTPAuthorizationCredentials = Depends(auth_scheme), db: Session = Depends(get_db)) -> User:
    ctx = get_auth(request, creds, db)
    return ctx['user']
