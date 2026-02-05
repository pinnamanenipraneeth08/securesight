"""
SecureSight - Alert Management Endpoints
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import structlog

from app.core.database import get_db
from app.core.security import get_current_user, TokenData
from app.core.elasticsearch import get_elasticsearch
from app.core.config import settings
from app.models.alert import Alert, AlertSeverity, AlertStatus

logger = structlog.get_logger()
router = APIRouter()


class AlertResponse(BaseModel):
    id: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    source_host: Optional[str]
    source_ip: Optional[str]
    rule_id: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    incident_id: Optional[str] = None


class AlertStats(BaseModel):
    total: int
    by_severity: dict
    by_status: dict


@router.get("/", response_model=List[AlertResponse])
async def list_alerts(
    severity: Optional[AlertSeverity] = None,
    status: Optional[AlertStatus] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    skip: int = 0,
    limit: int = 100,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List alerts with optional filters"""
    query = select(Alert)
    
    if severity:
        query = query.where(Alert.severity == severity)
    if status:
        query = query.where(Alert.status == status)
    if start_time:
        query = query.where(Alert.created_at >= start_time)
    if end_time:
        query = query.where(Alert.created_at <= end_time)
    
    query = query.order_by(Alert.created_at.desc()).offset(skip).limit(limit)
    
    result = await db.execute(query)
    alerts = result.scalars().all()
    
    return [
        AlertResponse(
            id=str(a.id),
            title=a.title,
            description=a.description,
            severity=a.severity.value,
            status=a.status.value,
            source_host=a.source_host,
            source_ip=a.source_ip,
            rule_id=str(a.rule_id) if a.rule_id else None,
            created_at=a.created_at,
        )
        for a in alerts
    ]


@router.get("/stats", response_model=AlertStats)
async def get_alert_stats(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get alert statistics"""
    # Total count
    total_query = select(func.count(Alert.id))
    if start_time:
        total_query = total_query.where(Alert.created_at >= start_time)
    if end_time:
        total_query = total_query.where(Alert.created_at <= end_time)
    
    result = await db.execute(total_query)
    total = result.scalar() or 0
    
    # By severity
    by_severity = {}
    for sev in AlertSeverity:
        query = select(func.count(Alert.id)).where(Alert.severity == sev)
        if start_time:
            query = query.where(Alert.created_at >= start_time)
        if end_time:
            query = query.where(Alert.created_at <= end_time)
        result = await db.execute(query)
        by_severity[sev.value] = result.scalar() or 0
    
    # By status
    by_status = {}
    for stat in AlertStatus:
        query = select(func.count(Alert.id)).where(Alert.status == stat)
        if start_time:
            query = query.where(Alert.created_at >= start_time)
        if end_time:
            query = query.where(Alert.created_at <= end_time)
        result = await db.execute(query)
        by_status[stat.value] = result.scalar() or 0
    
    return AlertStats(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get alert by ID"""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    return AlertResponse(
        id=str(alert.id),
        title=alert.title,
        description=alert.description,
        severity=alert.severity.value,
        status=alert.status.value,
        source_host=alert.source_host,
        source_ip=alert.source_ip,
        rule_id=str(alert.rule_id) if alert.rule_id else None,
        created_at=alert.created_at,
    )


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: str,
    update: AlertUpdate,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update alert status"""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    if update.status:
        alert.status = update.status
        if update.status == AlertStatus.ACKNOWLEDGED:
            alert.acknowledged_at = datetime.utcnow()
        elif update.status == AlertStatus.RESOLVED:
            alert.resolved_at = datetime.utcnow()
    
    if update.incident_id:
        alert.incident_id = update.incident_id
    
    await db.flush()
    
    logger.info("Alert updated", alert_id=alert_id, by=current_user.sub)
    
    return AlertResponse(
        id=str(alert.id),
        title=alert.title,
        description=alert.description,
        severity=alert.severity.value,
        status=alert.status.value,
        source_host=alert.source_host,
        source_ip=alert.source_ip,
        rule_id=str(alert.rule_id) if alert.rule_id else None,
        created_at=alert.created_at,
    )


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Acknowledge an alert"""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    alert.status = AlertStatus.ACKNOWLEDGED
    alert.acknowledged_at = datetime.utcnow()
    await db.flush()
    
    return {"status": "acknowledged", "alert_id": alert_id}
