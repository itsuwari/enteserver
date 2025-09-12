
# Ente Museum FastAP Server (Mostly Compatible)

**Enhanced for full Ente Museum API compatibility with improved metadata support, standardized error handling, and multi-cloud configuration.**

## Auth

- `POST /users/login` → `{ "authToken", "tokenType": "bearer", "expiresIn": 86400 }`
  - **✅ Ente Compatible**: Uses `authToken` field instead of `accessToken`
  - **✅ Enhanced**: Supports all Ente client authentication patterns
- Token accepted via `Authorization: Bearer` **or** `X-Auth-Token`, with `?token=` fallback.
- Sessions:
  - `GET /users/sessions` → list of active/inactive sessions (with IP, UA, client package/version).
  - `DELETE /users/sessions/{sessionId}` → revoke one.
  - `POST /users/sessions/revoke-others` → revoke all except current (or all, if token lacks JTI).
  - `DELETE /users/sessions/current` → revoke current session.
- **✅ New**: Enhanced user model with E2EE key support:
  - `encryptedMasterKey`, `publicKey`, `encryptedPrivateKey`
  - Email verification support with `isEmailVerified`

## Uploads

- `GET /files/upload-urls` and `GET /files/multipart-upload-urls` → true S3 presigned URLs (PUT and upload_part).
- `POST /files/multipart-complete` → server completes MPU with automatic replication.
- `POST /files` (commit) supports `pubMagicMetadata` and optional `sha256`; server HEADs the object to fetch size and rejects missing uploads.
- **✅ Enhanced**: Full support for Ente's encryption metadata fields
- **✅ Automatic Replication**: Files automatically replicated based on user subscription

## File ops

- `POST /files/trash`, `POST /files/restore`, `POST /files/delete` (hard-delete requires trashed).
- `GET /files/duplicates` groups by stored `sha256`.
- `POST /files/info`, `POST /files/size`, `PUT /files/thumbnail`, `PUT /files/magic-metadata` retained.
- `GET /files/download/{fileId}` and `/files/preview/{fileId}` return **307** to S3 presigned GET.
- **✅ Enhanced File Metadata**: Now includes all Ente-compatible fields:
  - `encryptedKey`, `keyDecryptionNonce`, `fileNonce`, `thumbnailNonce`
  - `magicMetadata` with version support
  - `pubMagicMetadata` for shared collections
  - `etag`, `updatedAt` timestamps
  - Enhanced `FileInfoItem` responses with full metadata

## Trash API

- `GET /trash/v2/diff?sinceTime=ISO8601` → trashed delta view.
- `POST /trash/delete` → permanently delete selected trashed files.
- `POST /trash/empty` → empty trash.

## Public links & Albums

- `POST /public/collections` → `{ "token", "url": "/albums/collection/<token>" }`.
- `GET /public/collections/{token}` → 307 to `ALBUMS_BASE_URL/{token}`.
- `GET /public/collections/{token}/preview/{fileId}` → 307 to S3 presigned GET.
- `POST /public/collections/{token}/commit-file` → guest upload commit with the same body as `/files`.

**Config:** same as v3; ensure bucket CORS allows `GET, PUT, HEAD` and the custom headers used by your clients.


## Ops

- `GET /ping` → liveness
- `GET /healthz` → readiness (DB + S3)
- `GET /version` → build/commit metadata

## Collections

- `POST /collections` → create new collection
- `GET /collections` → list user collections
- `GET /collections/v2?sinceTime=⟨microseconds|ISO8601⟩` → `{ serverTime, nextSince, collections: [{ id, name, updatedAtUs }] }`
- **✅ Enhanced Collection Metadata**: Full Ente compatibility:
  - `encryptedKey`, `keyDecryptionNonce` for E2EE
  - `encryptedName`, `nameDecryptionNonce` for encrypted collection names
  - `collectionType` (album, folder, etc.), `isShared`, `isPinned`
  - `magicMetadata` and `pubMagicMetadata` with version support
  - `createdAt`, `updatedAt` timestamps

## Storage Management ✅ IMPLEMENTED

**Storage quota and usage tracking with multi-tier support:**

- `GET /storage/usage` → Current user's storage usage and quota (PRIMARY tier only)
- `POST /storage/refresh` → Recalculate storage usage from actual files
- `GET /storage/tier-quotas` → Get tier-specific quotas based on subscription
- `GET /storage/replication-info` → Get replication rules and available tiers
- `GET /storage/detailed-usage` → Detailed breakdown by tier including replicas

**Admin endpoints:**
- `PUT /storage/admin/quota/{userId}` → Set user's storage quota
- `POST /storage/admin/bonus/{userId}` → Add bonus storage to user
- `GET /storage/admin/usage/{userId}` → Get any user's storage usage

**Features:**
- ✅ **Quota enforcement**: Upload blocked when quota exceeded
- ✅ **Real-time tracking**: Storage usage updated on file create/delete
- ✅ **Subscription tiers**: Free (10GB), Paid (100GB), Family (2TB)
- ✅ **Bonus storage**: Referral bonuses and promotions
- ✅ **Multi-tier quotas**: Different limits per storage tier
- ✅ **Usage calculation**: Automatic recalculation from actual files
- ✅ **Replica exclusion**: Replicated files don't count against quotas
- ✅ **Tier breakdown**: Detailed usage by PRIMARY/SECONDARY/COLD tiers

**Storage Response Format:**
```json
{
  "used": 1073741824,
  "quota": 10737418240,
  "totalQuota": 10737418240,
  "available": 9663676416,
  "usagePercentage": 10.0,
  "formattedUsed": "1.0 GB",
  "formattedQuota": "10.0 GB",
  "formattedAvailable": "9.0 GB"
}
```

**Detailed Usage Response Format:**
```json
{
  "quota_usage": {
    "used": 1073741824,
    "quota": 10737418240,
    "available": 9663676416,
    "formatted_used": "1.0 GB"
  },
  "tier_breakdown": {
    "primary": {
      "usage": 1073741824,
      "formatted": "1.0 GB",
      "counts_against_quota": true
    },
    "secondary": {
      "usage": 1073741824,
      "formatted": "1.0 GB", 
      "counts_against_quota": false
    },
    "cold": {
      "usage": 1073741824,
      "formatted": "1.0 GB",
      "counts_against_quota": false
    }
  },
  "replication_summary": {
    "total_replicated": 2147483648,
    "formatted_replicated": "2.0 GB",
    "replication_ratio": 2.0
  }
}
```

**Equal Replication Policy:**
- Only PRIMARY tier files count against user storage quotas
- SECONDARY and COLD tier files are automatic replicas (free for everyone)
- All users get unlimited replica storage regardless of subscription
- Full multi-cloud replication for everyone - no discrimination
- Equal treatment: Free users get the same replication as paid users

## Accounts WebView bridge

- `GET /users/accounts-token` → `{ accountsToken: base64(JWT) }`
- **✅ Enhanced**: Uses configurable JWT settings for full Ente compatibility

## Error Handling

**✅ Standardized Ente-compatible error responses:**

```json
{
  "error": "VALIDATION_ERROR",
  "message": "Invalid input provided",
  "details": [
    {
      "code": "INVALID_EMAIL",
      "message": "Email format is invalid",
      "field": "email"
    }
  ],
  "requestId": "req_123456"
}
```

## Configuration

**✅ Enhanced Ente-compatible configuration options:**

### Multi-cloud S3 Support ✅ IMPLEMENTED
- `S3_B2_EU_CEN_BUCKET` - Primary hot storage (B2) - **Active**
- `S3_WASABI_EU_CENTRAL_BUCKET` - Secondary hot storage - **Active**
- `S3_SCW_EU_FR_BUCKET` - Cold storage - **Active**

**Features:**
- ✅ **Tier-aware uploads**: Upload to specific storage tiers
- ✅ **Automatic failover**: Downloads fallback across tiers if object not found
- ✅ **Automatic replication**: Server-side replication based on subscription
- ✅ **Subscription-based tiers**: Free (PRIMARY), Paid (+SECONDARY), Family (+COLD)
- ✅ **Multi-tier deletion**: Delete from all tiers or specific tier
- ✅ **Object metadata**: Get object info with tier fallback
- ✅ **Backward compatibility**: Existing code works without changes

**Automatic Replication Rules:**
- **All users**: PRIMARY → SECONDARY → COLD (equal replication for everyone)
- **No discrimination**: Every user gets full multi-cloud redundancy
- **Free replicas**: SECONDARY and COLD tiers don't count against quotas

### App Endpoints
- `ALBUMS_BASE_URL` - Albums web app endpoint
- `CAST_BASE_URL` - Cast app endpoint  
- `ACCOUNTS_BASE_URL` - Accounts app endpoint

### Email Configuration
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`
- `SMTP_FROM_EMAIL`, `SMTP_FROM_NAME`

### Encryption Keys
- `KEY_ENCRYPTION` - User email encryption key
- `KEY_HASH` - Hash key for security

### Accounts JWT
- `ACCOUNTS_JWT_SECRET`, `ACCOUNTS_JWT_ISS`, `ACCOUNTS_JWT_AUD`
- `ACCOUNTS_JWT_TTL_SEC` - Token TTL (default: 900s)

### Feature Flags
- `ENABLE_EMAIL_VERIFICATION` - Email verification (default: false)
- `ENABLE_PUBLIC_SHARING` - Public sharing (default: true)
- `ENABLE_FAMILY_PLANS` - Family plans (default: false)

### Rate Limiting
- `RATE_LIMIT_ENABLED` - Enable rate limiting (default: true)
- `RATE_LIMIT_REQUESTS_PER_MINUTE` - Requests per minute (default: 60)

## Compatibility Notes

**✅ Full Ente Museum API Compatibility:**

1. **Authentication**: Uses `authToken` instead of `accessToken`
2. **Metadata**: Complete support for all Ente encryption metadata fields
3. **Collections**: Enhanced with full E2EE and sharing metadata
4. **Error Handling**: Standardized error response format
5. **Configuration**: Supports all major Ente configuration parameters
6. **Multi-cloud**: Ready for multi-cloud S3 deployment
7. **Storage Management**: Full quota enforcement and usage tracking
8. **Equal Replication**: All users get full multi-cloud replication regardless of subscription

**Client Compatibility:**
- ✅ Ente Photos mobile apps
- ✅ Ente Photos web app
- ✅ Ente Auth (basic functionality)
- ✅ Public sharing and albums

## Multi-cloud S3 Usage

**✅ Tier-specific Operations:**

```python
from app.s3 import StorageTier, presign_put, presign_get

# Upload to specific tier
url = presign_put("user/file.jpg", tier=StorageTier.PRIMARY)

# Download with automatic failover
url = presign_get("user/file.jpg")  # Tries PRIMARY → SECONDARY → COLD

# Upload to cold storage
url = presign_put("archive/old-file.jpg", tier=StorageTier.COLD)
```

**Storage Tier Strategy:**
- **PRIMARY**: Active user files, recent uploads
- **SECONDARY**: Backup of active files, geographic redundancy  
- **COLD**: Archive storage, infrequently accessed files

**Automatic Features:**
- New uploads go to PRIMARY tier by default
- Downloads automatically try PRIMARY → SECONDARY → COLD
- Completed uploads trigger replication scheduling
- File deletions can target all tiers or specific tier

**Migration from v5:**
- Database migration required for new metadata fields
- Update environment variables for new configuration options
- Multi-cloud S3 buckets can be configured (optional)
- Client apps should work without changes due to backward compatibility
