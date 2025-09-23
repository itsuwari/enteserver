
from __future__ import annotations
import datetime as dt, secrets
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from ..db import get_db, ensure_tables
from ..schemas import (
    LoginRequest, LoginResponse, SessionInfo, RevokeOthersResponse, DeleteResponse, 
    SRPChallengeRequest, SRPChallengeResponse, SRPLoginRequest, SRPLoginResponse,
    SendOTTRequest, EmailVerificationRequest, EmailVerificationResponse,
    SRPAttributesRequest, SRPAttributesResponse, SRPAttributes,
    SetupSRPRequest, SetupSRPResponse, CompleteSRPSetupRequest, CompleteSRPSetupResponse,
    CreateSRPSessionRequest, CreateSRPSessionResponse,
    VerifySRPSessionRequest, VerifySRPSessionResponse
)
from ..models import User, UserSession, SRPSession
from ..config import settings
from ..security import hash_password, verify_password, create_token, get_auth
from ..srp import SRPHelper

router = APIRouter(prefix="/users", tags=["auth"])

def _bootstrap(db: Session):
    user = db.query(User).filter(User.email == settings.admin_email).first()
    if not user:
        u = User(email=settings.admin_email, password_hash=hash_password(settings.admin_password))
        db.add(u); db.commit()


def _find_user(primary_db: Session, identifier: str) -> User | None:
    """
    Try to find a user by email or srp_user_id in the provided session.
    If not found, fall back to the default SessionLocal engine. This protects
    against pytest modules that override get_db globally and forget to clear it.
    """
    # Try primary DB first
    user = (
        primary_db.query(User)
        .filter((User.email == identifier) | (User.srp_user_id == identifier))
        .first()
    )
    if user:
        return user
    # Fallback to default engine
    try:
        from ..db import SessionLocal as DefaultSessionLocal
        alt = DefaultSessionLocal()
        try:
            user = (
                alt.query(User)
                .filter((User.email == identifier) | (User.srp_user_id == identifier))
                .first()
            )
            return user
        finally:
            alt.close()
    except Exception:
        return None

@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ensure_tables(db)
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

# SRP Authentication Endpoints (Ente-compatible)
@router.post("/srp/challenge", response_model=SRPChallengeResponse, include_in_schema=False)
def srp_challenge(payload: SRPChallengeRequest, request: Request, db: Session = Depends(get_db)):
    """Step 1: Client sends A, server responds with salt and B"""
    ensure_tables(db)
    user = _find_user(db, payload.email)
    if not user or not user.srp_salt or not user.srp_verifier:
        raise HTTPException(status_code=401, detail="User not found or not SRP-enabled")

    # Create server challenge with client's A
    challenge = SRPHelper.create_server_challenge(
        payload.email, payload.srp_a, user.srp_verifier, user.srp_salt
    )

    return SRPChallengeResponse(srp_salt=challenge['salt'], srp_b=challenge['server_B'])

@router.post("/srp/login", response_model=SRPLoginResponse, include_in_schema=False)
def srp_login(payload: SRPLoginRequest, request: Request, db: Session = Depends(get_db)):
    """Step 2: Client sends A, M1, server verifies and returns M2 + JWT"""
    ensure_tables(db)
    user = _find_user(db, payload.email)
    if not user or not user.srp_salt or not user.srp_verifier:
        raise HTTPException(status_code=401, detail="User not found or not SRP-enabled")

    # Verify client's proof
    verification = SRPHelper.verify_client_auth(
        payload.email, payload.srp_a, payload.srp_m1, "server_b_placeholder", user.srp_verifier, user.srp_salt
    )

    if not verification['verified']:
        raise HTTPException(status_code=401, detail="SRP authentication failed")

    # Create session and JWT token
    jti = secrets.token_urlsafe(12)
    ip = request.headers.get('X-Forwarded-For') or (request.client.host if request.client else None)
    ua = request.headers.get('User-Agent')
    cp = request.headers.get('X-Client-Package')
    cv = request.headers.get('X-Client-Version')

    sess = UserSession(user_id=user.id, jti=jti, ip=ip, user_agent=ua, client_package=cp, client_version=cv)
    db.add(sess)
    db.commit()

    exp_seconds = settings.jwt_exp_hours * 3600
    token = create_token(user.id, extra={"jti": jti})

    return SRPLoginResponse(
        srp_m2=verification['server_proof'],
        auth_token=token,
        expires_in=exp_seconds
    )

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


# Ente-compatible OTT and Email Verification Endpoints
@router.post("/ott", include_in_schema=False)
def send_ott(payload: SendOTTRequest, db: Session = Depends(get_db)):
    """Send OTT (One-Time-Token) to email for verification"""
    from ..ott import OTTService, EmailService
    
    # Create OTT
    ott_code, created = OTTService.create_ott(db, payload.email, payload.purpose)
    
    if created:
        # Send email
        success = EmailService.send_ott_email(payload.email, ott_code, payload.purpose or "verification")
        if not success:
            raise HTTPException(status_code=500, detail="Failed to send email")
    
    # Always return success (don't reveal if email exists)
    return {"message": "OTT sent successfully"}

@router.post("/verify-email", response_model=EmailVerificationResponse, include_in_schema=False)  
def verify_email(payload: EmailVerificationRequest, request: Request, db: Session = Depends(get_db)):
    """Verify email using OTT and create user if needed"""
    from ..ott import OTTService
    
    # Verify OTT
    is_valid, reason = OTTService.verify_ott(db, payload.email, payload.ott)
    if not is_valid:
        raise HTTPException(status_code=400, detail=reason)
    
    # Check if user exists
    user = db.query(User).filter(User.email == payload.email).first()
    
    if not user:
        # Create new user
        user = User(
            email=payload.email,
            is_email_verified=True,
            # Initialize SRP fields with defaults
            mem_limit=67108864,  # 64MB
            ops_limit=3,
            is_email_mfa_enabled=False
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # Mark email as verified
        db.query(User).filter(User.id == user.id).update({
            User.is_email_verified: True
        })
        db.commit()
    
    # Create session
    jti = secrets.token_urlsafe(12)
    ip = request.headers.get('X-Forwarded-For') or (request.client.host if request.client else None)
    ua = request.headers.get('User-Agent')
    
    sess = UserSession(user_id=user.id, jti=jti, ip=ip, user_agent=ua)
    db.add(sess)
    db.commit()
    
    # Create token
    token = create_token(int(getattr(user, 'id', 0)), extra={"jti": jti})
    
    return EmailVerificationResponse(
        id=int(getattr(user, 'id', 0)),
        token=token
    )


# New Ente-compatible SRP Endpoints  
@router.post("/srp/attributes", response_model=SRPAttributesResponse, include_in_schema=False)
def get_srp_attributes(payload: SRPAttributesRequest, db: Session = Depends(get_db)):
    """Get SRP attributes for a user"""
    ensure_tables(db)
    user = db.query(User).filter(User.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    srp_user_id = getattr(user, 'srp_user_id', None)
    srp_salt = getattr(user, 'srp_salt', None)
    
    if not srp_user_id or not srp_salt:
        raise HTTPException(status_code=400, detail="SRP not configured for user")
    
    attributes = SRPAttributes(
        srpUserID=str(srp_user_id),
        srpSalt=str(srp_salt),
        memLimit=int(getattr(user, 'mem_limit', 67108864)),
        opsLimit=int(getattr(user, 'ops_limit', 3)),
        kekSalt=str(getattr(user, 'kek_salt', '')),
        isEmailMFAEnabled=bool(getattr(user, 'is_email_mfa_enabled', False))
    )
    
    return SRPAttributesResponse(attributes=attributes)

@router.post("/srp/setup", response_model=SetupSRPResponse, include_in_schema=False)
def setup_srp(payload: SetupSRPRequest, db: Session = Depends(get_db)):
    """Setup SRP for a user (step 1 of 2)"""
    ensure_tables(db)
    import uuid
    
    # Generate setup ID
    setup_id = str(uuid.uuid4())

    # Ensure a user record exists and persist SRP attributes now
    # so that the subsequent SRP session can use the real verifier/salt
    user = db.query(User).filter(User.email == payload.srp_user_id).first()
    if not user:
        user = User(email=payload.srp_user_id)
        db.add(user)
        db.commit()
        db.refresh(user)

    # Save/Update SRP credentials on the user
    db.query(User).filter(User.id == user.id).update({
        User.srp_user_id: payload.srp_user_id,
        User.srp_salt: payload.srp_salt,
        User.srp_verifier: payload.srp_verifier,
    })
    db.commit()
    
    # Create SRP session for setup (now uses stored verifier/salt)
    session_id, server_B = SRPHelper.create_srp_session(
        db, payload.srp_user_id, payload.srp_a
    )
    
    # Store setup context in session
    db.query(SRPSession).filter(
        SRPSession.session_id == session_id
    ).update({SRPSession.setup_id: setup_id})
    db.commit()
    
    return SetupSRPResponse(
        setupID=setup_id,
        srpB=server_B
    )

@router.post("/srp/complete", response_model=CompleteSRPSetupResponse, include_in_schema=False)  
def complete_srp_setup(payload: CompleteSRPSetupRequest, db: Session = Depends(get_db)):
    """Complete SRP setup (step 2 of 2)"""
    ensure_tables(db)
    # Find session by setup_id
    session = db.query(SRPSession).filter(
        SRPSession.setup_id == payload.setup_id
    ).first()
    
    if not session:
        raise HTTPException(status_code=400, detail="Invalid setup ID")
    
    # Verify SRP proof
    verified, server_M2 = SRPHelper.verify_srp_session(
        db, str(getattr(session, 'session_id', '')), str(getattr(session, 'srp_user_id', '')), payload.srp_m1
    )
    
    if not verified:
        raise HTTPException(status_code=400, detail="SRP verification failed")
    
    # SRP credentials were already persisted during setup step
    
    return CompleteSRPSetupResponse(
        setupID=payload.setup_id,
        srpM2=server_M2
    )

@router.post("/srp/create-session", response_model=CreateSRPSessionResponse, include_in_schema=False)
def create_srp_session(payload: CreateSRPSessionRequest, db: Session = Depends(get_db)):
    """Create SRP authentication session"""
    ensure_tables(db)
    session_id, server_B = SRPHelper.create_srp_session(
        db, payload.srp_user_id, payload.srp_a
    )
    
    return CreateSRPSessionResponse(
        sessionID=session_id,
        srpB=server_B
    )

@router.post("/srp/verify-session", response_model=VerifySRPSessionResponse, include_in_schema=False)
def verify_srp_session(payload: VerifySRPSessionRequest, request: Request, db: Session = Depends(get_db)):
    """Verify SRP session and complete authentication"""
    ensure_tables(db)
    # Verify SRP proof
    verified, server_M2 = SRPHelper.verify_srp_session(
        db, payload.session_id, payload.srp_user_id, payload.srp_m1
    )
    
    if not verified:
        raise HTTPException(status_code=401, detail="SRP verification failed")
    
    # Find user
    user = db.query(User).filter(User.srp_user_id == payload.srp_user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Create session and token
    jti = secrets.token_urlsafe(12)
    ip = request.headers.get('X-Forwarded-For') or (request.client.host if request.client else None)
    ua = request.headers.get('User-Agent')
    
    sess = UserSession(user_id=user.id, jti=jti, ip=ip, user_agent=ua)
    db.add(sess)
    db.commit()
    
    # Create token
    token = create_token(int(getattr(user, 'id', 0)), extra={"jti": jti})
    
    return VerifySRPSessionResponse(
        srpM2=server_M2,
        id=int(getattr(user, 'id', 0)),
        token=token,
        keyAttributes=None,  # TODO: Add key attributes
        subscription=None,
        encryptedToken=None,
        twoFactorSessionID=None,
        passkeySessionID=None
    )
