# Photo API (development)

This repository contains a FastAPI server that mimics a small portion of the [Ente](https://ente.io) photo storage API.
The implementation is experimental and intended for local testing.  Only a subset of the real API is available and many
features are stubs.  Use this server only for development and with test data.

## Current features

### Authentication
- `POST /users/login` – email/password login returning `authToken`.
- Session management endpoints: `GET /users/sessions`, `DELETE /users/sessions/{id}`,
  `POST /users/sessions/revoke-others`, `DELETE /users/sessions/current`.
- User records contain fields for E2EE keys and email verification, but the verification flow is not implemented.

### File upload and management
- Presigned upload helpers: `GET /files/upload-urls`, `GET /files/multipart-upload-urls`, `POST /files/multipart-complete`.
- Commit uploaded files with metadata using `POST /files`.
- Update metadata: `PUT /files/update`, `PUT /files/thumbnail`, `PUT /files/magic-metadata`.
- Retrieve files via 307 redirects to S3: `GET /files/download/{id}` and `GET /files/preview/{id}`.
- Utility endpoints: `POST /files/info`, `POST /files/size`, `GET /files/duplicates`.
- Trash workflow: `POST /files/trash`, `POST /files/restore`, `POST /files/delete`.

### Collections
- Create and list collections: `POST /collections`, `GET /collections`.
- Delta listing: `GET /collections/v2?sinceTime=...`.
- Additional collection metadata fields are stored but not fully used by clients.

### Storage
- Uploads enforce a per‑user quota stored in the database.
- `/storage` endpoints report usage, tier quotas and replication information.
- Admin storage routes exist but do **not** include authentication; they are for development only.

### Public links
- `/public/collections` and related routes provide simple album links and optional guest uploads.
- `/public/files/{token}` serves individual file links.

### Operational endpoints
- `GET /ping` – liveness check.
- `GET /healthz` – readiness check (database and S3) returning `{"status": "ok"}` plus per-service details.
- `GET /version` – build metadata with `{"version": ..., "build": ...}`.

## Limitations
- Multi‑cloud replication is a placeholder: all tiers use the same S3 bucket unless separate buckets are configured.
- Advanced Ente features such as email verification, shared album permissions, family plans and full client compatibility are missing.
- Error handling and validation are minimal compared to the real service.
- This server has not been security audited and should not be exposed to the internet.

## Running locally
```
uvicorn app.main:app --reload
```

The server uses a local SQLite database file and supports one or more object storage
backends. Each backend can point to an S3-compatible service or a local filesystem
path. Configuration options are documented in `app/config.py` and can be provided
via environment variables.
