"""
One-Time-Token (OTT) system for email verification
Compatible with Ente mobile clients
"""

import secrets
import string
import datetime as dt
from typing import Optional
from sqlalchemy.orm import Session
from app.models import OneTimeToken


class OTTService:
    """Service for managing One-Time-Tokens for email verification"""
    
    OTT_LENGTH = 6
    OTT_EXPIRY_MINUTES = 10
    MAX_ATTEMPTS = 3
    RATE_LIMIT_WINDOW_MINUTES = 5
    MAX_TOKENS_PER_EMAIL = 3  # Max active tokens per email
    
    @staticmethod
    def generate_ott() -> str:
        """Generate a 6-digit OTT code"""
        return ''.join(secrets.choice(string.digits) for _ in range(OTTService.OTT_LENGTH))
    
    @classmethod
    def create_ott(
        cls, 
        db: Session, 
        email: str, 
        purpose: Optional[str] = None
    ) -> tuple[str, bool]:
        """
        Create a new OTT for email verification
        Returns (ott_code, created) where created indicates if new token was generated
        """
        # Clean up expired tokens first
        cls._cleanup_expired_tokens(db, email)
        
        # Check rate limiting - max tokens per email
        active_count = db.query(OneTimeToken).filter(
            OneTimeToken.email == email,
            ~OneTimeToken.is_used,
            OneTimeToken.expires_at > dt.datetime.utcnow()
        ).count()
        
        if active_count >= cls.MAX_TOKENS_PER_EMAIL:
            # Return the most recent active token instead of creating new one
            latest_token = db.query(OneTimeToken).filter(
                OneTimeToken.email == email,
                ~OneTimeToken.is_used,
                OneTimeToken.expires_at > dt.datetime.utcnow()
            ).order_by(OneTimeToken.created_at.desc()).first()
            
            if latest_token:
                return str(latest_token.ott), False
        
        # Generate new OTT
        ott_code = cls.generate_ott()
        expires_at = dt.datetime.utcnow() + dt.timedelta(minutes=cls.OTT_EXPIRY_MINUTES)
        
        # Create new token
        ott_token = OneTimeToken(
            email=email,
            ott=ott_code,
            purpose=purpose or "verification",
            expires_at=expires_at
        )
        
        db.add(ott_token)
        db.commit()
        
        return ott_code, True
    
    @classmethod 
    def verify_ott(
        cls, 
        db: Session, 
        email: str, 
        ott_code: str
    ) -> tuple[bool, str]:
        """
        Verify an OTT code for an email
        Returns (is_valid, reason)
        """
        # Find the token
        token = db.query(OneTimeToken).filter(
            OneTimeToken.email == email,
            OneTimeToken.ott == ott_code,
            ~OneTimeToken.is_used
        ).first()
        
        if not token:
            return False, "Invalid OTT code"
        
        # Check if expired
        if token.expires_at < dt.datetime.utcnow():
            return False, "OTT code has expired"
        
        # Check attempts
        if token.attempts >= token.max_attempts:
            return False, "Too many attempts"
        
        # Increment attempts and mark as used on successful verification
        db.query(OneTimeToken).filter(
            OneTimeToken.id == token.id
        ).update({
            OneTimeToken.attempts: OneTimeToken.attempts + 1,
            OneTimeToken.is_used: True
        })
        db.commit()
        
        return True, "OTT verified successfully"
    
    @classmethod
    def increment_attempt(
        cls,
        db: Session,
        email: str,
        ott_code: str
    ) -> bool:
        """
        Increment attempt counter for failed verification
        Returns True if token is still valid for more attempts
        """
        token = db.query(OneTimeToken).filter(
            OneTimeToken.email == email,
            OneTimeToken.ott == ott_code,
            ~OneTimeToken.is_used
        ).first()
        
        if not token:
            return False
        
        # Get current values and update attempts
        token_id = token.id
        current_attempts = getattr(token, 'attempts', 0)
        max_attempts = getattr(token, 'max_attempts', cls.MAX_ATTEMPTS)
        new_attempts = current_attempts + 1
        
        db.query(OneTimeToken).filter(
            OneTimeToken.id == token_id
        ).update({OneTimeToken.attempts: new_attempts})
        db.commit()
        
        return new_attempts < max_attempts
    
    @classmethod
    def _cleanup_expired_tokens(cls, db: Session, email: str):
        """Clean up expired tokens for an email"""
        expired_tokens = db.query(OneTimeToken).filter(
            OneTimeToken.email == email,
            OneTimeToken.expires_at < dt.datetime.utcnow()
        )
        
        expired_tokens.delete()
        db.commit()
    
    @classmethod
    def cleanup_all_expired(cls, db: Session):
        """Clean up all expired tokens (for periodic cleanup job)"""
        expired_tokens = db.query(OneTimeToken).filter(
            OneTimeToken.expires_at < dt.datetime.utcnow()
        )
        
        count = expired_tokens.count()
        expired_tokens.delete()
        db.commit()
        
        return count


class EmailService:
    """Mock email service - replace with actual email provider"""
    
    @staticmethod
    def send_ott_email(email: str, ott_code: str, purpose: str = "verification") -> bool:
        """
        Send OTT email to user
        Replace this with actual email service (SendGrid, SES, etc.)
        """
        # For development/testing - just log the OTT
        print(f"[EMAIL] Sending OTT to {email}: {ott_code} (purpose: {purpose})")
        
        # In production, implement actual email sending:
        # - Format email template with OTT code
        # - Send via email service provider
        # - Handle sending errors appropriately
        
        return True  # Always succeeds in mock implementation