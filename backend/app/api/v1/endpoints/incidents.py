"""
SecureSight - Incident Management Endpoints
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import structlog

from app.core.database import get_db
from app.core.security import get_current_user, TokenData
from app.models.incident import Incident, IncidentSeverity, IncidentStatus

logger = structlog.get_logger()
router = APIRouter()


class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    category: Optional[str] = None
    alert_ids: Optional[List[str]] = []


class IncidentResponse(BaseModel):
    id: str
    incident_number: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    category: Optional[str]
    assigned_to_id: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    category: Optional[str] = None
    assigned_to_id: Optional[str] = None


class TimelineEntry(BaseModel):
    action: str
    note: Optional[str] = None


class EvidenceItem(BaseModel):
    type: str
    name: str
    description: Optional[str] = None
    hash: Optional[str] = None
    path: Optional[str] = None


@router.get("/", response_model=List[IncidentResponse])
async def list_incidents(
    severity: Optional[IncidentSeverity] = None,
    status: Optional[IncidentStatus] = None,
    assigned_to: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List incidents with optional filters"""
    query = select(Incident)
    
    if severity:
        query = query.where(Incident.severity == severity)
    if status:
        query = query.where(Incident.status == status)
    if assigned_to:
        query = query.where(Incident.assigned_to_id == assigned_to)
    
    query = query.order_by(Incident.created_at.desc()).offset(skip).limit(limit)
    
    result = await db.execute(query)
    incidents = result.scalars().all()
    
    return [
        IncidentResponse(
            id=str(i.id),
            incident_number=i.incident_number,
            title=i.title,
            description=i.description,
            severity=i.severity.value,
            status=i.status.value,
            category=i.category,
            assigned_to_id=str(i.assigned_to_id) if i.assigned_to_id else None,
            created_at=i.created_at,
        )
        for i in incidents
    ]


@router.post("/", response_model=IncidentResponse)
async def create_incident(
    incident_data: IncidentCreate,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new incident"""
    incident = Incident(
        incident_number=Incident.generate_incident_number(),
        title=incident_data.title,
        description=incident_data.description,
        severity=incident_data.severity,
        category=incident_data.category,
        timeline=[{
            "timestamp": datetime.utcnow().isoformat(),
            "action": "created",
            "user_id": current_user.sub,
            "note": "Incident created"
        }],
    )
    
    db.add(incident)
    await db.flush()
    
    logger.info("Incident created", incident_id=str(incident.id), number=incident.incident_number)
    
    return IncidentResponse(
        id=str(incident.id),
        incident_number=incident.incident_number,
        title=incident.title,
        description=incident.description,
        severity=incident.severity.value,
        status=incident.status.value,
        category=incident.category,
        assigned_to_id=None,
        created_at=incident.created_at,
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get incident by ID"""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    return IncidentResponse(
        id=str(incident.id),
        incident_number=incident.incident_number,
        title=incident.title,
        description=incident.description,
        severity=incident.severity.value,
        status=incident.status.value,
        category=incident.category,
        assigned_to_id=str(incident.assigned_to_id) if incident.assigned_to_id else None,
        created_at=incident.created_at,
    )


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: str,
    update: IncidentUpdate,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update an incident"""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    changes = []
    
    if update.title is not None:
        incident.title = update.title
        changes.append("title")
    if update.description is not None:
        incident.description = update.description
        changes.append("description")
    if update.severity is not None:
        incident.severity = update.severity
        changes.append("severity")
    if update.status is not None:
        old_status = incident.status
        incident.status = update.status
        changes.append(f"status: {old_status.value} -> {update.status.value}")
        
        if update.status == IncidentStatus.CONTAINED:
            incident.contained_at = datetime.utcnow()
        elif update.status == IncidentStatus.REMEDIATED:
            incident.resolved_at = datetime.utcnow()
        elif update.status == IncidentStatus.CLOSED:
            incident.closed_at = datetime.utcnow()
    
    if update.category is not None:
        incident.category = update.category
        changes.append("category")
    if update.assigned_to_id is not None:
        incident.assigned_to_id = update.assigned_to_id
        changes.append("assignment")
    
    # Add to timeline
    if incident.timeline is None:
        incident.timeline = []
    incident.timeline.append({
        "timestamp": datetime.utcnow().isoformat(),
        "action": "updated",
        "user_id": current_user.sub,
        "changes": changes,
    })
    
    await db.flush()
    
    logger.info("Incident updated", incident_id=incident_id, changes=changes)
    
    return IncidentResponse(
        id=str(incident.id),
        incident_number=incident.incident_number,
        title=incident.title,
        description=incident.description,
        severity=incident.severity.value,
        status=incident.status.value,
        category=incident.category,
        assigned_to_id=str(incident.assigned_to_id) if incident.assigned_to_id else None,
        created_at=incident.created_at,
    )


@router.post("/{incident_id}/timeline")
async def add_timeline_entry(
    incident_id: str,
    entry: TimelineEntry,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add entry to incident timeline"""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    if incident.timeline is None:
        incident.timeline = []
    
    incident.timeline.append({
        "timestamp": datetime.utcnow().isoformat(),
        "action": entry.action,
        "user_id": current_user.sub,
        "note": entry.note,
    })
    
    await db.flush()
    
    return {"status": "added", "timeline_length": len(incident.timeline)}


@router.post("/{incident_id}/evidence")
async def add_evidence(
    incident_id: str,
    evidence: EvidenceItem,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add evidence to incident"""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    if incident.evidence is None:
        incident.evidence = []
    
    incident.evidence.append({
        "type": evidence.type,
        "name": evidence.name,
        "description": evidence.description,
        "hash": evidence.hash,
        "path": evidence.path,
        "added_by": current_user.sub,
        "added_at": datetime.utcnow().isoformat(),
    })
    
    await db.flush()
    
    return {"status": "added", "evidence_count": len(incident.evidence)}
