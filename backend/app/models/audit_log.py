"""
SecureSight - Audit Log Model
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.core.database import Base


class AuditLog(Base):
    """Audit log for tracking user actions"""
    
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Action details
    action = Column(String(100), nullable=False)  # e.g., "user.login", "rule.create"
    resource_type = Column(String(100))  # e.g., "user", "rule", "alert"
    resource_id = Column(String(100))  # ID of the affected resource
    
    # Description
    description = Column(Text)
    
    # User who performed the action
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    user = relationship("User", back_populates="audit_logs")
    username = Column(String(100))  # Stored for quick access
    
    # Request context
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    
    # Data changes (for update operations)
    # Example: {"before": {...}, "after": {...}}
    changes = Column(JSON)
    
    # Status
    status = Column(String(50))  # "success" or "failure"
    error_message = Column(Text)
    
    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    @classmethod
    def create_log(
        cls,
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        description: Optional[str] = None,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        changes: Optional[dict] = None,
        status: str = "success",
        error_message: Optional[str] = None,
    ) -> "AuditLog":
        """Factory method to create audit log entry"""
        return cls(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            changes=changes,
            status=status,
            error_message=error_message,
        )
