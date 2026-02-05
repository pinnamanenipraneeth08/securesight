"""
SecureSight - User Model
"""

from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Enum, ForeignKey, Table
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
import enum

from app.core.database import Base


class UserRole(str, enum.Enum):
    """User roles"""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# User-Role association table
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id"), primary_key=True),
    Column("role", Enum(UserRole), primary_key=True),
)


class User(Base):
    """User model for authentication and authorization"""
    
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # MFA fields
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(32), nullable=True)  # Base32 encoded TOTP secret
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Relationships
    incidents_assigned = relationship("Incident", back_populates="assigned_to")
    audit_logs = relationship("AuditLog", back_populates="user")
    
    # Roles (stored in association table)
    roles = Column(String(255), default="viewer")  # Comma-separated roles
    
    def get_roles(self) -> list[str]:
        """Get list of roles"""
        return [r.strip() for r in self.roles.split(",")] if self.roles else []
    
    def has_role(self, role: str) -> bool:
        """Check if user has a specific role"""
        return role in self.get_roles()
