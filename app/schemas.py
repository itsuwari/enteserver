
from __future__ import annotations
import datetime as dt
from pydantic import BaseModel, Field

class CamelModel(BaseModel):
    model_config = {"populate_by_name": True, "alias_generator": lambda s: ''.join([s.split('_')[0]] + [w.capitalize() for w in s.split('_')[1:]])}

# ---- Auth

# Legacy login (remove after SRP migration)
class LoginRequest(CamelModel):
    email: str
    password: str

class LoginResponse(CamelModel):
    auth_token: str = Field(alias="authToken")
    token_type: str = "bearer"
    expires_in: int | None = Field(default=None, alias="expiresIn")

# SRP Authentication (Ente-compatible)
class SRPChallengeRequest(CamelModel):
    email: str
    srp_a: str = Field(alias="srpA")  # Client's public key A

class SRPChallengeResponse(CamelModel):
    srp_salt: str = Field(alias="srpSalt")
    srp_b: str = Field(alias="srpB")  # Server's public key B

class SRPLoginRequest(CamelModel):
    email: str
    srp_a: str = Field(alias="srpA")  # Client's public key A
    srp_m1: str = Field(alias="srpM1")  # Client's proof M1

class SRPLoginResponse(CamelModel):
    srp_m2: str = Field(alias="srpM2")  # Server's proof M2
    auth_token: str = Field(alias="authToken")  # JWT after SRP verification
    token_type: str = "bearer"
    expires_in: int | None = Field(default=None, alias="expiresIn")

# OTT (One-Time-Token) Email Verification
class SendOTTRequest(CamelModel):
    email: str
    purpose: str | None = None  # "signup", "login", "change", etc.
    mobile: bool = False

class EmailVerificationRequest(CamelModel):
    email: str
    ott: str
    source: str | None = None  # Referral source

class EmailVerificationResponse(CamelModel):
    id: int
    token: str
    key_attributes: dict | None = Field(default=None, alias="keyAttributes")
    subscription: dict | None = None

# New SRP Endpoints (Ente-compatible)
class SRPAttributesRequest(CamelModel):
    email: str

class SRPAttributesResponse(CamelModel):
    attributes: "SRPAttributes"

class SRPAttributes(CamelModel):
    srp_user_id: str = Field(alias="srpUserID")
    srp_salt: str = Field(alias="srpSalt")
    mem_limit: int = Field(alias="memLimit")
    ops_limit: int = Field(alias="opsLimit")
    kek_salt: str = Field(alias="kekSalt")
    is_email_mfa_enabled: bool = Field(alias="isEmailMFAEnabled")

class SetupSRPRequest(CamelModel):
    srp_user_id: str = Field(alias="srpUserID")
    srp_salt: str = Field(alias="srpSalt")
    srp_verifier: str = Field(alias="srpVerifier")
    srp_a: str = Field(alias="srpA")
    is_update: bool = Field(default=False, alias="isUpdate")

class SetupSRPResponse(CamelModel):
    setup_id: str = Field(alias="setupID")
    srp_b: str = Field(alias="srpB")

class CompleteSRPSetupRequest(CamelModel):
    setup_id: str = Field(alias="setupID")
    srp_m1: str = Field(alias="srpM1")

class CompleteSRPSetupResponse(CamelModel):
    setup_id: str = Field(alias="setupID")
    srp_m2: str = Field(alias="srpM2")

class CreateSRPSessionRequest(CamelModel):
    srp_user_id: str = Field(alias="srpUserID")
    srp_a: str = Field(alias="srpA")

class CreateSRPSessionResponse(CamelModel):
    session_id: str = Field(alias="sessionID")
    srp_b: str = Field(alias="srpB")

class VerifySRPSessionRequest(CamelModel):
    session_id: str = Field(alias="sessionID")
    srp_user_id: str = Field(alias="srpUserID")
    srp_m1: str = Field(alias="srpM1")

class VerifySRPSessionResponse(CamelModel):
    srp_m2: str = Field(alias="srpM2")
    id: int
    token: str | None = None
    key_attributes: dict | None = Field(default=None, alias="keyAttributes")
    subscription: dict | None = None
    encrypted_token: str | None = Field(default=None, alias="encryptedToken")
    two_factor_session_id: str | None = Field(default=None, alias="twoFactorSessionID")
    passkey_session_id: str | None = Field(default=None, alias="passkeySessionID")

class SessionInfo(CamelModel):
    id: int
    created_at: dt.datetime | None = Field(default=None, alias="createdAt")
    last_seen_at: dt.datetime | None = Field(default=None, alias="lastSeenAt")
    ip: str | None = None
    user_agent: str | None = Field(default=None, alias="userAgent")
    client_package: str | None = Field(default=None, alias="clientPackage")
    client_version: str | None = Field(default=None, alias="clientVersion")
    active: bool = True

class RevokeOthersResponse(CamelModel):
    revoked: int

class DeleteResponse(CamelModel):
    deleted: int

# ---- Upload URLs

class UploadURL(CamelModel):
    object_key: str = Field(alias="objectKey")
    url: str

class UploadURLResponse(CamelModel):
    urls: list[UploadURL]

class MultipartUploadURLs(CamelModel):
    object_key: str = Field(alias="objectKey")
    upload_id: str = Field(alias="uploadId")
    part_urls: list[str] = Field(alias="partUrls")
    complete_url: str | None = Field(default=None, alias="completeUrl")

class MultipartUploadURLsResponse(CamelModel):
    urls: list[MultipartUploadURLs]

class MultipartCompleteItem(CamelModel):
    part_number: int = Field(alias="partNumber")
    e_tag: str = Field(alias="eTag")

class MultipartCompleteRequest(CamelModel):
    object_key: str = Field(alias="objectKey")
    upload_id: str = Field(alias="uploadId")
    parts: list[MultipartCompleteItem]

# ---- Files

class EncryptedObject(CamelModel):
    decryption_header: str | None = Field(default=None, alias="decryptionHeader")
    object_key: str = Field(alias="objectKey")

class EncryptedMetadata(CamelModel):
    decryption_header: str = Field(alias="decryptionHeader")
    encrypted_data: str = Field(alias="encryptedData")

class MagicMetadata(CamelModel):
    header: str | None = None
    data: str | None = None
    version: int | None = None

class PubMagicMetadata(CamelModel):
    version: int | None = None
    count: int | None = None
    header: str | None = None
    data: str | None = None

class FileCreate(CamelModel):
    collection_id: int | None = Field(default=None, alias="collectionID")
    encrypted_key: str | None = Field(default=None, alias="encryptedKey")
    key_decryption_nonce: str | None = Field(default=None, alias="keyDecryptionNonce")
    file: EncryptedObject
    thumbnail: EncryptedObject | None = None
    metadata: EncryptedMetadata | None = None
    magic_metadata: MagicMetadata | None = Field(default=None, alias="magicMetadata")
    pub_magic_metadata: PubMagicMetadata | None = Field(default=None, alias="pubMagicMetadata")
    original_filename: str | None = Field(default=None, alias="originalFilename")
    mime_type: str | None = Field(default=None, alias="mimeType")
    sha256: str | None = None

class FileUpdate(CamelModel):
    file_id: int = Field(alias="fileId")
    collection_id: int | None = Field(default=None, alias="collectionID")
    thumbnail: EncryptedObject | None = None
    metadata: EncryptedMetadata | None = None
    magic_metadata: MagicMetadata | None = Field(default=None, alias="magicMetadata")
    original_filename: str | None = Field(default=None, alias="originalFilename")
    mime_type: str | None = Field(default=None, alias="mimeType")

class FileIDsRequest(CamelModel):
    file_ids: list[int] = Field(alias="fileIds")

class SizeResponse(CamelModel):
    size: int

class FileInfoItem(CamelModel):
    id: int
    object_key: str | None = Field(default=None, alias="objectKey")
    size: int | None = None
    sha256: str | None = None
    created_at: dt.datetime | None = Field(default=None, alias="createdAt")
    updated_at: dt.datetime | None = Field(default=None, alias="updatedAt")
    mime_type: str | None = Field(default=None, alias="mimeType")
    collection_id: int | None = Field(default=None, alias="collectionID")
    is_trashed: bool = Field(default=False, alias="isTrashed")
    
    # Additional metadata for compatibility
    etag: str | None = None
    encrypted_key: str | None = Field(default=None, alias="encryptedKey")
    key_decryption_nonce: str | None = Field(default=None, alias="keyDecryptionNonce")
    file_nonce: str | None = Field(default=None, alias="fileNonce")
    thumbnail_nonce: str | None = Field(default=None, alias="thumbnailNonce")
    
    # Magic metadata
    magic_metadata: MagicMetadata | None = Field(default=None, alias="magicMetadata")
    pub_magic_metadata: PubMagicMetadata | None = Field(default=None, alias="pubMagicMetadata")

class FilesInfoResponse(CamelModel):
    files: list[FileInfoItem]

class UpdateThumbnailRequest(CamelModel):
    file_id: int = Field(alias="fileId")
    object_key: str = Field(alias="objectKey")

class UpdateMultipleMagicMetadataItem(CamelModel):
    file_id: int = Field(alias="fileId")
    magic_metadata: MagicMetadata = Field(alias="magicMetadata")

class UpdateMultipleMagicMetadataRequest(CamelModel):
    items: list[UpdateMultipleMagicMetadataItem]

class PreviewURLResponse(CamelModel):
    url: str

class TrashItem(CamelModel):
    file_id: int = Field(alias="fileId")

class TrashRequest(CamelModel):
    items: list[TrashItem]

class DuplicatesGroup(CamelModel):
    file_ids: list[int] = Field(alias="fileIds")
    size: int | None = None
    sha256: str

class DuplicatesResponse(CamelModel):
    duplicates: list[DuplicatesGroup]

# ---- Trash

class DeleteTrashFilesRequest(CamelModel):
    file_ids: list[int] = Field(alias="fileIds")

class EmptyTrashRequest(CamelModel):
    confirm: bool = True

class TrashDiffItem(CamelModel):
    file_id: int = Field(alias="fileId")
    trashed_at: dt.datetime | None = Field(default=None, alias="trashedAt")
    is_trashed: bool = Field(alias="isTrashed")

class TrashDiffResponse(CamelModel):
    items: list[TrashDiffItem]

# ---- Collections & Public links

class CollectionCreate(CamelModel):
    name: str

class CollectionResponse(CamelModel):
    id: int
    name: str
    created_at: dt.datetime | None = Field(default=None, alias="createdAt")
    updated_at: dt.datetime | None = Field(default=None, alias="updatedAt")
    
    # Collection metadata for compatibility
    collection_type: str | None = Field(default=None, alias="type")
    is_shared: bool = Field(default=False, alias="isShared")
    is_pinned: bool = Field(default=False, alias="isPinned")
    
    # Encryption metadata
    encrypted_key: str | None = Field(default=None, alias="encryptedKey")
    key_decryption_nonce: str | None = Field(default=None, alias="keyDecryptionNonce")
    encrypted_name: str | None = Field(default=None, alias="encryptedName")
    name_decryption_nonce: str | None = Field(default=None, alias="nameDecryptionNonce")
    
    # Magic metadata
    magic_metadata: MagicMetadata | None = Field(default=None, alias="magicMetadata")
    pub_magic_metadata: PubMagicMetadata | None = Field(default=None, alias="pubMagicMetadata")

class PublicCollectionCreate(CamelModel):
    collection_id: int = Field(alias="collectionID")
    allow_upload: bool = Field(default=False, alias="allowUpload")
    password: str | None = None
    expires_in_seconds: int | None = Field(default=None, alias="expiresInSeconds")

class PublicLinkResponse(CamelModel):
    token: str
    url: str

# ---- Error Handling

class ErrorDetail(CamelModel):
    code: str
    message: str
    field: str | None = None

class ErrorResponse(CamelModel):
    error: str
    message: str
    details: list[ErrorDetail] | None = None
    request_id: str | None = Field(default=None, alias="requestId")

class ValidationErrorResponse(CamelModel):
    error: str = "VALIDATION_ERROR"
    message: str
    errors: list[ErrorDetail]

# ---- Storage Management

class StorageUsageResponse(CamelModel):
    used: int
    quota: int
    bonus: int = 0
    total_quota: int = Field(alias="totalQuota")
    available: int
    usage_percentage: float = Field(alias="usagePercentage")
    formatted_used: str = Field(alias="formattedUsed")
    formatted_quota: str = Field(alias="formattedQuota")
    formatted_available: str = Field(alias="formattedAvailable")

class StorageQuotaUpdate(CamelModel):
    new_quota: int = Field(alias="newQuota")
    
class StorageBonusAdd(CamelModel):
    bonus_bytes: int = Field(alias="bonusBytes")
    reason: str | None = None

class StorageQuotaExceededError(CamelModel):
    error: str = "STORAGE_QUOTA_EXCEEDED"
    message: str
    used: int
    quota: int
    requested: int
    available: int
