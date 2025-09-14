from __future__ import annotations
import html
import jwt, secrets, datetime as dt
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from botocore.exceptions import BotoCoreError, ClientError

from ..db import get_db
from ..models import User, UserInvite
from ..config import settings
from ..security import verify_password, create_token
from .auth import _bootstrap
from .. import s3 as s3mod

router = APIRouter(prefix="/admin", tags=["admin"], include_in_schema=False)


def _get_admin_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"], options={"verify_aud": False})
        user_id = int(payload.get("sub"))
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.get(User, user_id)
    if not user or user.email != settings.admin_email:
        raise HTTPException(status_code=403, detail="Forbidden")
    return user


@router.get("/", response_class=HTMLResponse)
def admin_index(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("token")
    if token:
        try:
            payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"], options={"verify_aud": False})
            user_id = int(payload.get("sub"))
            user = db.get(User, user_id)
            if user and user.email == settings.admin_email:
                return HTMLResponse(
                    "<h1>Admin Dashboard</h1>" \
                    "<ul>" \
                    "<li><a href='/admin/users'>Manage Users</a></li>" \
                    "<li><a href='/admin/bucket'>Bucket Usage</a></li>" \
                    "<li><a href='/admin/logout'>Logout</a></li>" \
                    "</ul>"
                )
        except jwt.PyJWTError:
            pass
    return HTMLResponse(
        "<h1>Admin Login</h1>" \
        "<form method='post' action='/admin/login'>" \
        "Email: <input type='text' name='email'/><br/>" \
        "Password: <input type='password' name='password'/><br/>" \
        "<input type='submit' value='Login'/></form>"
    )


@router.post("/login")
def admin_login(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    _bootstrap(db)
    user = db.query(User).filter(User.email == email).first()
    if not user or user.email != settings.admin_email or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user.id)
    response = RedirectResponse(url="/admin", status_code=303)
    response.set_cookie("token", token, httponly=True)
    return response


@router.get("/logout")
def admin_logout():
    response = RedirectResponse(url="/admin", status_code=303)
    response.delete_cookie("token")
    return response


@router.get("/users", response_class=HTMLResponse)
def list_users(admin: User = Depends(_get_admin_user), db: Session = Depends(get_db)):
    users = db.query(User).all()
    rows = "".join(
        f"<tr><td>{u.id}</td><td>{html.escape(u.email)}</td><td>{u.storage_used}</td><td>{u.storage_quota}</td>" \
        f"<td><form method='post' action='/admin/users/delete'><input type='hidden' name='user_id' value='{u.id}'/><input type='submit' value='Delete'/></form></td></tr>"
        for u in users
    )
    html = (
        "<h1>Users</h1>" \
        "<table border='1'><tr><th>ID</th><th>Email</th><th>Used</th><th>Quota</th><th>Actions</th></tr>" + rows + "</table>" \
        "<h2>Invite User</h2>" \
        "<form method='post' action='/admin/users/invite'>" \
        "Email: <input type='text' name='email'/><br/>" \
        "<input type='submit' value='Invite'/></form>" \
        "<p><a href='/admin'>Back</a></p>"
    )
    return HTMLResponse(html)


@router.post("/users/invite", response_class=HTMLResponse)
def invite_user(email: str = Form(...), admin: User = Depends(_get_admin_user), db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="User exists")
    token = secrets.token_urlsafe(32)
    inv = UserInvite(email=email, token=token, expires_at=dt.datetime.utcnow() + dt.timedelta(days=7))
    db.add(inv)
    db.commit()
    link = f"/invite/accept?token={token}"
    html = (
        "<h1>Invite Created</h1>" \
        f"<p>Share this link with {html.escape(email)}: <a href='{html.escape(link)}'>{html.escape(link)}</a></p>" \
        "<p><a href='/admin/users'>Back</a></p>"
    )
    return HTMLResponse(html)


@router.post("/users/delete")
def delete_user(user_id: int = Form(...), admin: User = Depends(_get_admin_user), db: Session = Depends(get_db)):
    if admin.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete self")
    u = db.get(User, user_id)
    if u:
        db.delete(u)
        db.commit()
    return RedirectResponse(url="/admin/users", status_code=303)


@router.get("/bucket", response_class=HTMLResponse)
def bucket_info(admin: User = Depends(_get_admin_user)):
    if not settings.s3_enabled:
        return HTMLResponse("<h1>S3 disabled</h1><p><a href='/admin'>Back</a></p>")
    try:
        client = s3mod._client()
        bucket = s3mod._bucket()
        total_size = 0
        total_count = 0
        token = None
        while True:
            kwargs = {"Bucket": bucket}
            if token:
                kwargs["ContinuationToken"] = token
            resp = client.list_objects_v2(**kwargs)
            for obj in resp.get("Contents", []):
                total_count += 1
                total_size += obj.get("Size", 0)
            if resp.get("IsTruncated"):
                token = resp.get("NextContinuationToken")
            else:
                break
        html = (
            f"<h1>Bucket {html.escape(bucket)}</h1>" \
            f"<p>Objects: {total_count}<br/>Total size: {total_size} bytes</p>" \
            "<p><a href='/admin'>Back</a></p>"
        )
    except (BotoCoreError, ClientError) as e:
        html = f"<h1>Error: {html.escape(str(e))}</h1><p><a href='/admin'>Back</a></p>"
    return HTMLResponse(html)
