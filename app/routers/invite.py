from __future__ import annotations
import datetime as dt
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..db import get_db
from ..models import UserInvite, User
from ..security import create_token
from ..config import settings
from ..schemas import LoginResponse
from ..srp import SRPHelper

router = APIRouter(prefix="/invite", tags=["invite"], include_in_schema=False)

class AcceptInviteRequest(BaseModel):
    token: str
    password: str

@router.post("/accept", response_model=LoginResponse)
def accept_invite(payload: AcceptInviteRequest, db: Session = Depends(get_db)):
    inv = db.query(UserInvite).filter(UserInvite.token == payload.token, UserInvite.consumed == False).first()
    if not inv:
        raise HTTPException(status_code=400, detail="Invalid token")
    if inv.expires_at and inv.expires_at < dt.datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invite expired")
    if db.query(User).filter(User.email == inv.email).first():
        raise HTTPException(status_code=400, detail="User exists")

    # Generate SRP parameters for user registration
    srp_salt = SRPHelper.generate_salt()
    srp_verifier = SRPHelper.generate_verifier(inv.email, payload.password, srp_salt)

    u = User(
        email=inv.email,
        srp_salt=srp_salt,
        srp_verifier=srp_verifier
    )
    db.add(u)
    db.flush()  # Get user ID

    inv.consumed = True
    db.commit()

    exp_seconds = settings.jwt_exp_hours * 3600
    token = create_token(u.id)
    return LoginResponse(auth_token=token, expires_in=exp_seconds)
