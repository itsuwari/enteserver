
from __future__ import annotations

import argparse
import getpass
import sys
import secrets
import datetime as dt
from typing import Optional

from .db import Base, engine, SessionLocal
from .models import User, UserInvite
from .security import hash_password
from .config import settings
from .storage import (
    get_user_storage_usage, set_user_storage_quota, add_storage_bonus,
    format_storage_size, update_user_storage_usage
)

def _ensure_db():
    Base.metadata.create_all(bind=engine)

def _open_session():
    return SessionLocal()

def _print_user(u: User, show_storage: bool = False):
    print(f"id={u.id} email={u.email} created_at={u.created_at}")
    if show_storage:
        quota_gb = u.storage_quota / (1024**3)
        used_gb = u.storage_used / (1024**3)
        bonus_gb = u.storage_bonus / (1024**3)
        total_quota_gb = (u.storage_quota + u.storage_bonus) / (1024**3)
        print(f"  storage: {used_gb:.2f}GB / {total_quota_gb:.2f}GB (quota: {quota_gb:.2f}GB, bonus: {bonus_gb:.2f}GB)")
        print(f"  subscription: {u.subscription_type}")

def invite_user(email: str):
    _ensure_db()
    db = _open_session()
    try:
        if db.query(User).filter(User.email == email).first():
            print("Error: user already exists", file=sys.stderr)
            sys.exit(1)
        token = secrets.token_urlsafe(32)
        inv = UserInvite(email=email, token=token, expires_at=dt.datetime.utcnow() + dt.timedelta(days=7))
        db.add(inv)
        db.commit()
        link = f"/invite/accept?token={token}"
        print(f"Invite link for {email}: {link}")
    finally:
        db.close()

def change_user_password(email: str, password: Optional[str] = None, prompt: bool = False):
    if prompt or not password:
        pw1 = getpass.getpass("New password: ")
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print("Error: passwords do not match", file=sys.stderr)
            sys.exit(2)
        password = pw1
    _ensure_db()
    db = _open_session()
    try:
        u = db.query(User).filter(User.email == email).first()
        if not u:
            print("Error: user not found", file=sys.stderr)
            sys.exit(1)
        u.password_hash = hash_password(password)
        db.commit()
        print("Password updated.")
    finally:
        db.close()

def change_admin_password(email: Optional[str] = None, password: Optional[str] = None, prompt: bool = False):
    email = email or settings.admin_email
    change_user_password(email=email, password=password, prompt=prompt)

def change_admin_username(current_email: Optional[str], new_email: str):
    curr = current_email or settings.admin_email
    _ensure_db()
    db = _open_session()
    try:
        admin = db.query(User).filter(User.email == curr).first()
        if not admin:
            print(f"Error: admin user with email '{curr}' not found", file=sys.stderr)
            sys.exit(1)
        if db.query(User).filter(User.email == new_email).first():
            print("Error: target email already in use", file=sys.stderr)
            sys.exit(1)
        admin.email = new_email
        db.commit()
        print(f"Admin email changed: {curr} -> {new_email}")
    finally:
        db.close()

def list_users(show_storage: bool = False):
    _ensure_db()
    db = _open_session()
    try:
        users = db.query(User).order_by(User.id.asc()).all()
        for u in users:
            _print_user(u, show_storage)
        if not users:
            print("(no users)")
    finally:
        db.close()

def set_storage_quota(email: str, quota_gb: float):
    """Set storage quota for a user (in GB)"""
    _ensure_db()
    db = _open_session()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            print(f"Error: user '{email}' not found", file=sys.stderr)
            sys.exit(1)
        
        quota_bytes = int(quota_gb * 1024**3)
        old_quota_gb = user.storage_quota / (1024**3)
        
        success = set_user_storage_quota(user.id, quota_bytes, db)
        if success:
            print(f"Storage quota updated for {email}: {old_quota_gb:.2f}GB -> {quota_gb:.2f}GB")
            _print_user(user, show_storage=True)
        else:
            print(f"Error: failed to update storage quota for {email}", file=sys.stderr)
            sys.exit(1)
    finally:
        db.close()

def add_storage_bonus_cli(email: str, bonus_gb: float, reason: str = None):
    """Add bonus storage to a user (in GB)"""
    _ensure_db()
    db = _open_session()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            print(f"Error: user '{email}' not found", file=sys.stderr)
            sys.exit(1)
        
        bonus_bytes = int(bonus_gb * 1024**3)
        old_bonus_gb = user.storage_bonus / (1024**3)
        
        success = add_storage_bonus(user.id, bonus_bytes, db)
        if success:
            new_bonus_gb = (user.storage_bonus + bonus_bytes) / (1024**3)
            print(f"Bonus storage added for {email}: {old_bonus_gb:.2f}GB -> {new_bonus_gb:.2f}GB (+{bonus_gb:.2f}GB)")
            if reason:
                print(f"Reason: {reason}")
            # Refresh user object to show updated values
            db.refresh(user)
            _print_user(user, show_storage=True)
        else:
            print(f"Error: failed to add bonus storage for {email}", file=sys.stderr)
            sys.exit(1)
    finally:
        db.close()

def show_storage_usage(email: str):
    """Show detailed storage usage for a user"""
    _ensure_db()
    db = _open_session()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            print(f"Error: user '{email}' not found", file=sys.stderr)
            sys.exit(1)
        
        usage_info = get_user_storage_usage(user.id, db)
        if "error" in usage_info:
            print(f"Error: {usage_info['error']}", file=sys.stderr)
            sys.exit(1)
        
        print(f"Storage usage for {email}:")
        print(f"  Used: {format_storage_size(usage_info['used'])}")
        print(f"  Quota: {format_storage_size(usage_info['quota'])}")
        print(f"  Bonus: {format_storage_size(usage_info['bonus'])}")
        print(f"  Total Quota: {format_storage_size(usage_info['total_quota'])}")
        print(f"  Available: {format_storage_size(usage_info['available'])}")
        print(f"  Usage: {usage_info['usage_percentage']:.1f}%")
        print(f"  Subscription: {user.subscription_type}")
        
        # Check if stored usage differs from calculated usage
        if usage_info['used'] != usage_info['stored_used']:
            print(f"  ⚠️  Stored usage differs from calculated: {format_storage_size(usage_info['stored_used'])}")
            print(f"     Run 'refresh-storage-usage --email {email}' to fix this.")
    finally:
        db.close()

def refresh_storage_usage_cli(email: str):
    """Recalculate and update storage usage from actual files"""
    _ensure_db()
    db = _open_session()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            print(f"Error: user '{email}' not found", file=sys.stderr)
            sys.exit(1)
        
        old_usage = user.storage_used
        usage_info = update_user_storage_usage(user.id, db)
        
        if "error" in usage_info:
            print(f"Error: {usage_info['error']}", file=sys.stderr)
            sys.exit(1)
        
        print(f"Storage usage refreshed for {email}:")
        print(f"  Old usage: {format_storage_size(old_usage)}")
        print(f"  New usage: {format_storage_size(usage_info['used'])}")
        print(f"  Difference: {format_storage_size(usage_info['used'] - old_usage)}")
    finally:
        db.close()

def set_subscription_type(email: str, subscription_type: str):
    """Set subscription type for a user"""
    valid_types = ["free", "paid", "family"]
    if subscription_type not in valid_types:
        print(f"Error: invalid subscription type '{subscription_type}'. Valid types: {', '.join(valid_types)}", file=sys.stderr)
        sys.exit(1)
    
    _ensure_db()
    db = _open_session()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            print(f"Error: user '{email}' not found", file=sys.stderr)
            sys.exit(1)
        
        old_type = user.subscription_type
        user.subscription_type = subscription_type
        db.commit()
        
        print(f"Subscription type updated for {email}: {old_type} -> {subscription_type}")
        _print_user(user, show_storage=True)
    finally:
        db.close()

def _help(parser, cmd_parsers, command=None):
    if not command:
        parser.print_help()
        return
    sp = cmd_parsers.get(command)
    if sp is None:
        print(f"Unknown command: {command}", file=sys.stderr)
        parser.print_help()
        sys.exit(1)
    sp.print_help()

def main(argv=None):
    parser = argparse.ArgumentParser(prog="museum-cli", description="Museum subset – user management CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)
    cmd_parsers = {}

    p_inv = sub.add_parser("invite-user", help="Create an invite link for a new user"); cmd_parsers['invite-user'] = p_inv
    p_inv.add_argument("--email", required=True)
    p_inv.set_defaults(func=lambda a: invite_user(a.email))

    p_cup = sub.add_parser("change-user-password", help="Change a user's password"); cmd_parsers['change-user-password'] = p_cup
    p_cup.add_argument("--email", required=True)
    pw_grp = p_cup.add_mutually_exclusive_group()
    pw_grp.add_argument("--password")
    pw_grp.add_argument("--prompt", action="store_true")
    p_cup.set_defaults(func=lambda a: change_user_password(a.email, a.password, a.prompt))

    p_cap = sub.add_parser("change-admin-password", help="Change admin password"); cmd_parsers['change-admin-password'] = p_cap
    p_cap.add_argument("--email", help="Admin email (defaults to Settings.admin_email)")
    pw_grp2 = p_cap.add_mutually_exclusive_group()
    pw_grp2.add_argument("--password")
    pw_grp2.add_argument("--prompt", action="store_true")
    p_cap.set_defaults(func=lambda a: change_admin_password(a.email, a.password, a.prompt))

    p_cau = sub.add_parser("change-admin-username", help="Change admin username (email)"); cmd_parsers['change-admin-username'] = p_cau
    p_cau.add_argument("--current-email", dest="current_email", help="Current admin email (defaults to Settings.admin_email)")
    p_cau.add_argument("--new-email", dest="new_email", required=True)
    p_cau.set_defaults(func=lambda a: change_admin_username(a.current_email, a.new_email))

    p_ls = sub.add_parser("list-users", help="List users"); cmd_parsers['list-users'] = p_ls
    p_ls.add_argument("--show-storage", action="store_true", help="Show storage information")
    p_ls.set_defaults(func=lambda a: list_users(a.show_storage))

    # Storage management commands
    p_quota = sub.add_parser("set-storage-quota", help="Set storage quota for a user"); cmd_parsers['set-storage-quota'] = p_quota
    p_quota.add_argument("--email", required=True, help="User email")
    p_quota.add_argument("--quota-gb", type=float, required=True, help="Storage quota in GB")
    p_quota.set_defaults(func=lambda a: set_storage_quota(a.email, a.quota_gb))

    p_bonus = sub.add_parser("add-storage-bonus", help="Add bonus storage to a user"); cmd_parsers['add-storage-bonus'] = p_bonus
    p_bonus.add_argument("--email", required=True, help="User email")
    p_bonus.add_argument("--bonus-gb", type=float, required=True, help="Bonus storage in GB")
    p_bonus.add_argument("--reason", help="Reason for bonus storage")
    p_bonus.set_defaults(func=lambda a: add_storage_bonus_cli(a.email, a.bonus_gb, a.reason))

    p_usage = sub.add_parser("show-storage-usage", help="Show detailed storage usage for a user"); cmd_parsers['show-storage-usage'] = p_usage
    p_usage.add_argument("--email", required=True, help="User email")
    p_usage.set_defaults(func=lambda a: show_storage_usage(a.email))

    p_refresh = sub.add_parser("refresh-storage-usage", help="Recalculate storage usage from actual files"); cmd_parsers['refresh-storage-usage'] = p_refresh
    p_refresh.add_argument("--email", required=True, help="User email")
    p_refresh.set_defaults(func=lambda a: refresh_storage_usage_cli(a.email))

    p_sub = sub.add_parser("set-subscription", help="Set subscription type for a user"); cmd_parsers['set-subscription'] = p_sub
    p_sub.add_argument("--email", required=True, help="User email")
    p_sub.add_argument("--type", choices=["free", "paid", "family"], required=True, help="Subscription type")
    p_sub.set_defaults(func=lambda a: set_subscription_type(a.email, a.type))

    p_help = sub.add_parser("help", help="Show help or help for a command"); cmd_parsers['help'] = p_help
    p_help.add_argument("command", nargs="?")
    p_help.set_defaults(func=lambda a: _help(parser, cmd_parsers, a.command))

    args = parser.parse_args(argv)
    args.func(args)

if __name__ == "__main__":
    main()
