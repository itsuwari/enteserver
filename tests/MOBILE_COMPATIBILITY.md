# Ente Mobile Client Compatibility Testing Guide

This guide provides comprehensive testing procedures to verify compatibility with Ente mobile clients.

## Automated Test Suite

Run the automated compatibility tests:

```bash
cd /path/to/enteserver
python -m pytest tests/test_ente_compatibility.py -v
```

This test suite covers:
- ✅ OTT email verification flow
- ✅ SRP attribute retrieval  
- ✅ SRP session management
- ✅ SRP setup flow
- ✅ Field naming conventions (camelCase)
- ✅ API endpoint existence
- ✅ Request/response schema validation

## Manual Testing with cURL

### 1. OTT Email Verification Flow

#### Send OTT
```bash
curl -X POST http://localhost:8000/users/ott \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "purpose": "signup",
    "mobile": true
  }'
```

#### Verify Email with OTT
```bash
curl -X POST http://localhost:8000/users/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com", 
    "ott": "123456",
    "source": "mobile"
  }'
```

### 2. SRP Authentication Flow

#### Get SRP Attributes
```bash
curl -X POST http://localhost:8000/users/srp/attributes \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com"
  }'
```

#### Create SRP Session
```bash
curl -X POST http://localhost:8000/users/srp/create-session \
  -H "Content-Type: application/json" \
  -d '{
    "srpUserID": "test@example.com",
    "srpA": "base64_encoded_client_A_value"
  }'
```

#### Verify SRP Session
```bash  
curl -X POST http://localhost:8000/users/srp/verify-session \
  -H "Content-Type: application/json" \
  -d '{
    "sessionID": "session_id_from_create",
    "srpUserID": "test@example.com",
    "srpM1": "client_proof_m1"
  }'
```

### 3. SRP Setup Flow

#### Setup SRP (Step 1)
```bash
curl -X POST http://localhost:8000/users/srp/setup \
  -H "Content-Type: application/json" \
  -d '{
    "srpUserID": "test@example.com",
    "srpSalt": "base64_salt",
    "srpVerifier": "base64_verifier",
    "srpA": "base64_client_A"
  }'
```

#### Complete SRP Setup (Step 2)
```bash
curl -X POST http://localhost:8000/users/srp/complete \
  -H "Content-Type: application/json" \
  -d '{
    "setupID": "setup_id_from_step1",
    "srpM1": "client_proof_m1"
  }'
```

## Mobile Client Integration Testing

### Prerequisites
1. **Server Setup**: Ensure server is running with new compatibility features
2. **Database Migration**: Run migration scripts for new tables/fields
3. **Email Service**: Configure email service for OTT delivery (or use console logging for testing)

### Expected Mobile Client Flow

#### Initial Registration
1. **User enters email** → Mobile app calls `/users/ott`
2. **User receives OTT email** → App prompts for 6-digit code
3. **User enters OTT** → App calls `/users/verify-email`
4. **Server creates user** → Returns JWT token for authenticated session

#### SRP Authentication Setup  
1. **User sets password** → App generates SRP salt, verifier
2. **App calls `/users/srp/setup`** → Initiates SRP setup
3. **App completes cryptographic proof** → Calls `/users/srp/complete`
4. **SRP credentials saved** → User can now login with SRP

#### Subsequent Logins
1. **User enters email** → App calls `/users/srp/attributes`
2. **App gets SRP parameters** → Prepares SRP authentication
3. **App calls `/users/srp/create-session`** → Starts auth session
4. **User enters password** → App generates proof, calls `/users/srp/verify-session`
5. **Server verifies proof** → Returns JWT token for authenticated session

## Compatibility Checklist

### ✅ API Endpoints
- [x] `POST /users/ott` - Send OTT email
- [x] `POST /users/verify-email` - Verify email with OTT  
- [x] `POST /users/srp/attributes` - Get SRP attributes
- [x] `POST /users/srp/setup` - Setup SRP (step 1)
- [x] `POST /users/srp/complete` - Complete SRP setup (step 2)
- [x] `POST /users/srp/create-session` - Create SRP session
- [x] `POST /users/srp/verify-session` - Verify SRP session

### ✅ Request/Response Schema
- [x] Field names use camelCase (srpUserID, isEmailMFAEnabled, etc.)
- [x] Proper field aliases for Pydantic models
- [x] Required vs optional fields match Ente expectations
- [x] Error responses include proper detail messages

### ✅ Database Schema
- [x] User model has all required SRP fields
- [x] OneTimeToken table for OTT management
- [x] SRPSession table for session management
- [x] Proper field types and constraints

### ✅ Cryptographic Implementation
- [x] SRP-6a protocol with RFC 5054 2048-bit parameters
- [x] Proper session management and state tracking
- [x] Secure random number generation
- [x] Base64 encoding for binary data

### ✅ Security Features
- [x] OTT rate limiting and expiration
- [x] SRP session timeout and cleanup
- [x] Email verification before account creation
- [x] Secure password hashing fallback

## Common Issues and Troubleshooting

### OTT Issues
- **OTT not received**: Check email service configuration and logs
- **Invalid OTT error**: Verify 6-digit format and expiration time
- **Rate limiting**: Check OTT attempt limits and timeouts

### SRP Issues  
- **Attribute errors**: Ensure user has SRP configured (srp_user_id, srp_salt)
- **Session failures**: Check SRP session expiration and cleanup
- **Verification failures**: Verify SRP implementation matches client expectations

### Field Name Issues
- **Validation errors**: Ensure request uses camelCase field names
- **Missing fields**: Check Pydantic model aliases and required fields
- **Type errors**: Verify data types match schema expectations

## Integration with Real Ente Mobile App

To test with the actual Ente mobile application:

1. **Build custom Ente mobile app** pointing to your server
2. **Configure server URL** in mobile app settings
3. **Test complete user journey**: Registration → Setup → Login → File operations
4. **Monitor server logs** for compatibility issues
5. **Compare API calls** with official Ente server using network inspection

Note: This requires access to Ente mobile app source code and ability to configure custom server endpoints.