"""
SecureSight - Alert Model
"""

from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, Enum, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
import enum

from app.core.database import Base


class AlertSeverity(str, enum.Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, enum.Enum):
    """Alert status"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ESCALATED = "escalated"


class Alert(Base):
    """Alert model for security alerts"""
    
    __tablename__ = "alerts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Alert identification
    title = Column(String(500), nullable=False)
    description = Column(Text)
    
    # Severity and status
    severity = Column(Enum(AlertSeverity), nullable=False, default=AlertSeverity.MEDIUM)
    status = Column(Enum(AlertStatus), nullable=False, default=AlertStatus.NEW)
    
    # Source information
    source_host = Column(String(255))
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    
    # Rule that triggered the alert
    rule_id = Column(UUID(as_uuid=True), ForeignKey("rules.id"), nullable=True)
    rule = relationship("Rule", back_populates="alerts")
    
    # Links to incident
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True)
    incident = relationship("Incident", back_populates="alerts")
    
    # Additional data
    matched_logs = Column(JSON)  # List of log IDs that matched
    alert_metadata = Column(JSON)  # Additional context
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    acknowledged_at = Column(DateTime)
    resolved_at = Column(DateTime)
    
    # Deduplication
    fingerprint = Column(String(64), index=True)  # Hash for deduplication
    occurrence_count = Column(String(10), default="1")  # Number of occurrences
    last_occurrence = Column(DateTime)
