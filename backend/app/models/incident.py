"""
SecureSight - Incident Model
"""

from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, Enum, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
import enum

from app.core.database import Base


class IncidentSeverity(str, enum.Enum):
    """Incident severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(str, enum.Enum):
    """Incident status"""
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    CLOSED = "closed"


class Incident(Base):
    """Incident model for case management"""
    
    __tablename__ = "incidents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Incident identification
    incident_number = Column(String(50), unique=True, nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    
    # Classification
    severity = Column(Enum(IncidentSeverity), nullable=False, default=IncidentSeverity.MEDIUM)
    status = Column(Enum(IncidentStatus), nullable=False, default=IncidentStatus.OPEN)
    category = Column(String(100))  # e.g., "malware", "phishing", "unauthorized_access"
    
    # Assignment
    assigned_to_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    assigned_to = relationship("User", back_populates="incidents_assigned")
    
    # Related items
    alerts = relationship("Alert", back_populates="incident")
    
    # Timeline and notes (append-only log)
    # Example: [{"timestamp": "...", "action": "created", "user": "...", "note": "..."}]
    timeline = Column(JSON, default=list)
    
    # Evidence and artifacts
    # Example: [{"type": "file", "name": "malware.exe", "hash": "...", "path": "..."}]
    evidence = Column(JSON, default=list)
    
    # Affected assets
    affected_hosts = Column(JSON, default=list)
    affected_users = Column(JSON, default=list)
    
    # MITRE ATT&CK mapping
    attack_tactics = Column(JSON, default=list)
    attack_techniques = Column(JSON, default=list)
    
    # Resolution
    root_cause = Column(Text)
    remediation_steps = Column(Text)
    lessons_learned = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    detected_at = Column(DateTime)
    contained_at = Column(DateTime)
    resolved_at = Column(DateTime)
    closed_at = Column(DateTime)
    
    @staticmethod
    def generate_incident_number() -> str:
        """Generate unique incident number"""
        timestamp = datetime.utcnow().strftime("%Y%m%d")
        random_suffix = str(uuid.uuid4())[:6].upper()
        return f"INC-{timestamp}-{random_suffix}"
