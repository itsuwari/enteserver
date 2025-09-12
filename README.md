
# Museum using FastAPI

This is the FastAPI backend for the Museum project.
Original https://github.com/ente-io/ente/tree/main/server
We are trying to be compatible, provide a lighrter, easier to use server.
There is a docker file but I highly recommend you just use the py version, its faster, and you should change settings.


Run:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export ADMIN_EMAIL="admin@example.com"
export ADMIN_PASSWORD="changeme"
export JWT_SECRET="dev-secret"

export S3_ENABLED=1
export S3_ENDPOINT_URL="http://localhost:9000"
export S3_REGION="us-east-1"
export S3_ACCESS_KEY="minioadmin"
export S3_SECRET_KEY="minioadmin"
export S3_BUCKET="ente-objects"
export S3_USE_PATH_STYLE=1
export ALBUMS_BASE_URL="http://localhost:3002"

uvicorn app.main:app --reload
# Swagger: http://localhost:8000/docs
```

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
