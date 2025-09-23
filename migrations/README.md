# Database Migrations

This directory contains database migration scripts for the Ente-compatible photo backup server.

## Running Migrations

### Automatic Migration (Recommended for Development)
The server automatically creates missing tables and columns on startup using SQLAlchemy's `create_all()`. No manual intervention required.

### Manual Migration (Recommended for Production)
For production deployments, run migrations manually before starting the server:

```bash
cd /path/to/enteserver
python migrations/001_ente_compatibility.py
```

## Migration: 001_ente_compatibility.py

This migration adds Ente mobile client compatibility by:

### User Table Updates
- `srp_user_id`: SRP user identifier (usually email)
- `kek_salt`: Key encryption key salt for E2EE
- `mem_limit`: Argon2 memory limit (default: 64MB)
- `ops_limit`: Argon2 operations limit (default: 3)
- `is_email_mfa_enabled`: Email MFA enabled flag

### New Tables
- `one_time_tokens`: For OTT (One-Time-Token) email verification
  - 6-digit codes with expiration and rate limiting
  - Used by `/users/ott` and `/users/verify-email` endpoints

- `srp_sessions`: For SRP-6a protocol session management
  - Secure session storage for SRP authentication flow
  - Used by new SRP endpoints for proper protocol handling

## New API Endpoints Added

### OTT and Email Verification
- `POST /users/ott` - Send OTT to email
- `POST /users/verify-email` - Verify email with OTT

### SRP Authentication (Ente-compatible)
- `POST /users/srp/attributes` - Get user SRP attributes
- `POST /users/srp/setup` - Setup SRP (step 1)
- `POST /users/srp/complete` - Complete SRP setup (step 2)  
- `POST /users/srp/create-session` - Create SRP auth session
- `POST /users/srp/verify-session` - Verify SRP session

## Rollback

This migration only adds new columns and tables. To rollback:
1. Drop the new tables: `one_time_tokens`, `srp_sessions`
2. Remove the new columns from `users` table (optional)

**Warning**: Rolling back will lose OTT and SRP session data.