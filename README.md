
# Museum using FastAPI

This is the FastAPI backend for the Museum project.
Original https://github.com/ente-io/ente/tree/main/server
We are trying to be compatible, provide a lighrter, easier to use server.
There is a docker file but I highly recommend you just use the py version, its faster, and you should change settings.

Run:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config.example.toml config.toml
# edit config.toml as needed (env vars override values)
uvicorn app.main:app --reload
# Swagger: http://localhost:8000/docs
```

### Configuration

Runtime configuration is centralized through the `app/config` package. Edit
`config.toml` (or point the `CONFIG_FILE` environment variable to another
TOML file) to override settings; the Python modules import the generated
`Settings` object from `app.config`. This keeps a single source of truth for
application options while still giving tests and scripts a convenient
`config.override(...)` helper when temporary adjustments are required.

### Object storage configuration

The server now supports multiple storage backends simultaneously. Each backend
can be an S3-compatible service or a local filesystem path. Define the desired
mix of backends in the `[s3.backends]` section of `config.toml`. For example,
you can configure a local directory as the primary tier and still replicate
objects to a remote S3 bucket, or use multiple local folders for additional
redundancy. See `config.example.toml` for a sample configuration that combines
an S3 bucket with a local path. When a local backend is active the server
exposes signed URLs under `/local-storage/...` that behave like S3 presigned
links for uploads, downloads, and multipart uploads. These endpoints are served
by the FastAPI app itself so all storage traffic stays on the same port as the
rest of the API.

CLI:

```bash
# User management
python -m app.cli help
python -m app.cli list-users --show-storage
python -m app.cli add-user --email user@example.com --prompt
python -m app.cli change-admin-password --prompt
python -m app.cli change-admin-username --new-email new-admin@example.com

# Storage management
python -m app.cli set-storage-quota --email user@example.com --quota-gb 50
python -m app.cli add-storage-bonus --email user@example.com --bonus-gb 5 --reason "Welcome bonus"
python -m app.cli show-storage-usage --email user@example.com
python -m app.cli refresh-storage-usage --email user@example.com
python -m app.cli set-subscription --email user@example.com --type paid (Just a tier name, IAP money goes to ente)
```
