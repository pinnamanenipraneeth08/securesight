"""
SecureSight - Detection Rule Model
"""

from datetime import datetime
from sqlalchemy import Column, String, Text, Boolean, DateTime, Enum, Integer, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
import enum

from app.core.database import Base


class RuleType(str, enum.Enum):
    """Types of detection rules"""
    THRESHOLD = "threshold"
    CORRELATION = "correlation"
    SIGNATURE = "signature"
    ANOMALY = "anomaly"
    CUSTOM = "custom"


class RuleSeverity(str, enum.Enum):
    """Rule severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Rule(Base):
    """Detection rule model"""
    
    __tablename__ = "rules"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Rule identification
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Rule configuration
    rule_type = Column(Enum(RuleType), nullable=False, default=RuleType.THRESHOLD)
    severity = Column(Enum(RuleSeverity), nullable=False, default=RuleSeverity.MEDIUM)
    
    # Rule logic (JSON format)
    # Example:
    # {
    #     "conditions": [
    #         {"field": "event_type", "operator": "equals", "value": "login_failed"},
    #         {"field": "source_ip", "operator": "not_in", "value": ["10.0.0.0/8"]}
    #     ],
    #     "threshold": 5,
    #     "time_window": 300,  # seconds
    #     "group_by": ["source_ip", "username"]
    # }
    logic = Column(JSON, nullable=False)
    
    # Rule behavior
    is_enabled = Column(Boolean, default=True)
    is_test_mode = Column(Boolean, default=False)  # Don't generate real alerts
    
    # Response actions
    # Example: ["email", "slack", "block_ip"]
    actions = Column(JSON, default=list)
    
    # MITRE ATT&CK mapping
    mitre_tactic = Column(String(100))
    mitre_technique = Column(String(100))
    
    # Metadata
    tags = Column(JSON, default=list)
    author = Column(String(255))
    version = Column(String(20), default="1.0")
    
    # Performance
    hit_count = Column(Integer, default=0)
    last_triggered = Column(DateTime)
    false_positive_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    alerts = relationship("Alert", back_populates="rule")
    
    def to_dict(self):
        """Convert rule to dictionary for detection engine"""
        return {
            "id": str(self.id),
            "name": self.name,
            "type": self.rule_type.value,
            "severity": self.severity.value,
            "logic": self.logic,
            "actions": self.actions or [],
            "is_enabled": self.is_enabled,
            "is_test_mode": self.is_test_mode,
        }
