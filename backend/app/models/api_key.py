"""
SecureSight - API Key Model
"""

from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
import secrets
import hashlib

from app.core.database import Base


def generate_api_key() -> str:
    """Generate a secure API key"""
    return f"sk_{secrets.token_urlsafe(32)}"


def hash_api_key(key: str) -> str:
    """Hash an API key for storage"""
    return hashlib.sha256(key.encode()).hexdigest()


class ApiKey(Base):
    """API Key model for agent authentication"""
    
    __tablename__ = "api_keys"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Store hashed key, not the actual key
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    
    # Store prefix for identification (first 8 chars)
    key_prefix = Column(String(12), nullable=False)
    
    # Owner
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    user = relationship("User", backref="api_keys")
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Usage tracking
    last_used_at = Column(DateTime, nullable=True)
    usage_count = Column(String(20), default="0")  # String to avoid integer overflow
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)  # Optional expiration
    
    def is_expired(self) -> bool:
        """Check if the API key has expired"""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if the API key is valid (active and not expired)"""
        return self.is_active and not self.is_expired()
    
    @classmethod
    def create_key(cls, name: str, user_id: uuid.UUID, description: str = None, expires_at: datetime = None):
        """Create a new API key and return both the model and the raw key"""
        raw_key = generate_api_key()
        key_hash = hash_api_key(raw_key)
        key_prefix = raw_key[:12]
        
        api_key = cls(
            name=name,
            description=description,
            key_hash=key_hash,
            key_prefix=key_prefix,
            user_id=user_id,
            expires_at=expires_at,
        )
        
        return api_key, raw_key
    
    @classmethod
    def verify_key(cls, raw_key: str) -> str:
        """Hash a raw key for verification"""
        return hash_api_key(raw_key)
