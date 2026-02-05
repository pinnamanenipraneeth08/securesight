"""
SecureSight - Dashboard Endpoints
"""

from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import structlog

from app.core.database import get_db
from app.core.security import get_current_user, TokenData
from app.core.elasticsearch import get_elasticsearch
from app.core.redis import get_redis, LogQueue
from app.core.config import settings
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.incident import Incident, IncidentStatus
from app.models.rule import Rule

logger = structlog.get_logger()
router = APIRouter()


class DashboardStats(BaseModel):
    """Main dashboard statistics"""
    total_alerts: int
    critical_alerts: int
    open_incidents: int
    active_rules: int
    logs_today: int
    queue_length: int


class AlertTrend(BaseModel):
    """Alert trend data point"""
    timestamp: str
    count: int
    severity: str


class TopAttacker(BaseModel):
    """Top attacker entry"""
    ip: str
    count: int
    country: Optional[str] = None


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get main dashboard statistics"""
    # Total alerts
    result = await db.execute(select(func.count(Alert.id)))
    total_alerts = result.scalar() or 0
    
    # Critical alerts (unresolved)
    result = await db.execute(
        select(func.count(Alert.id)).where(
            Alert.severity == AlertSeverity.CRITICAL,
            Alert.status.not_in([AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE])
        )
    )
    critical_alerts = result.scalar() or 0
    
    # Open incidents
    result = await db.execute(
        select(func.count(Incident.id)).where(
            Incident.status.not_in([IncidentStatus.CLOSED, IncidentStatus.REMEDIATED])
        )
    )
    open_incidents = result.scalar() or 0
    
    # Active rules
    result = await db.execute(
        select(func.count(Rule.id)).where(Rule.is_enabled == True)
    )
    active_rules = result.scalar() or 0
    
    # Logs today (from Elasticsearch)
    logs_today = 0
    try:
        es = get_elasticsearch()
        today = datetime.utcnow().strftime("%Y.%m.%d")
        index = f"{settings.ELASTICSEARCH_INDEX_PREFIX}-logs-{today}"
        
        result = await es.count(index=index)
        logs_today = result.get("count", 0)
    except Exception:
        pass
    
    # Queue length
    queue = LogQueue()
    queue_length = await queue.length()
    
    return DashboardStats(
        total_alerts=total_alerts,
        critical_alerts=critical_alerts,
        open_incidents=open_incidents,
        active_rules=active_rules,
        logs_today=logs_today,
        queue_length=queue_length,
    )


@router.get("/alerts/trend")
async def get_alert_trend(
    hours: int = 24,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get alert trend over time"""
    start_time = datetime.utcnow() - timedelta(hours=hours)
    
    # Get alerts grouped by hour and severity
    result = await db.execute(
        select(Alert)
        .where(Alert.created_at >= start_time)
        .order_by(Alert.created_at)
    )
    alerts = result.scalars().all()
    
    # Group by hour
    hourly_data = {}
    for alert in alerts:
        hour_key = alert.created_at.strftime("%Y-%m-%d %H:00")
        if hour_key not in hourly_data:
            hourly_data[hour_key] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        hourly_data[hour_key][alert.severity.value] += 1
    
    # Convert to list
    trend = []
    for timestamp, counts in sorted(hourly_data.items()):
        for severity, count in counts.items():
            if count > 0:
                trend.append({
                    "timestamp": timestamp,
                    "count": count,
                    "severity": severity,
                })
    
    return {"hours": hours, "data": trend}


@router.get("/top-attackers")
async def get_top_attackers(
    hours: int = 24,
    limit: int = 10,
    current_user: TokenData = Depends(get_current_user),
):
    """Get top attacking IPs from logs"""
    try:
        es = get_elasticsearch()
        index = f"{settings.ELASTICSEARCH_INDEX_PREFIX}-logs-*"
        
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
                        {"terms": {"event_type": ["login_failed", "attack", "brute_force", "port_scan"]}}
                    ]
                }
            },
            "aggs": {
                "top_ips": {
                    "terms": {
                        "field": "network.src_ip",
                        "size": limit
                    }
                }
            }
        }
        
        result = await es.search(index=index, body=body)
        
        buckets = result.get("aggregations", {}).get("top_ips", {}).get("buckets", [])
        
        return {
            "hours": hours,
            "attackers": [
                {"ip": b["key"], "count": b["doc_count"]}
                for b in buckets
            ]
        }
        
    except Exception as e:
        logger.warning("Top attackers query failed", error=str(e))
        return {"hours": hours, "attackers": []}


@router.get("/event-types")
async def get_event_types(
    hours: int = 24,
    current_user: TokenData = Depends(get_current_user),
):
    """Get distribution of event types"""
    try:
        es = get_elasticsearch()
        index = f"{settings.ELASTICSEARCH_INDEX_PREFIX}-logs-*"
        
        body = {
            "size": 0,
            "query": {
                "range": {"timestamp": {"gte": f"now-{hours}h"}}
            },
            "aggs": {
                "event_types": {
                    "terms": {
                        "field": "event_type",
                        "size": 20
                    }
                }
            }
        }
        
        result = await es.search(index=index, body=body)
        
        buckets = result.get("aggregations", {}).get("event_types", {}).get("buckets", [])
        
        return {
            "hours": hours,
            "event_types": [
                {"type": b["key"], "count": b["doc_count"]}
                for b in buckets
            ]
        }
        
    except Exception as e:
        logger.warning("Event types query failed", error=str(e))
        return {"hours": hours, "event_types": []}


@router.get("/hosts")
async def get_active_hosts(
    hours: int = 24,
    current_user: TokenData = Depends(get_current_user),
):
    """Get list of active hosts sending logs"""
    try:
        es = get_elasticsearch()
        index = f"{settings.ELASTICSEARCH_INDEX_PREFIX}-logs-*"
        
        body = {
            "size": 0,
            "query": {
                "range": {"timestamp": {"gte": f"now-{hours}h"}}
            },
            "aggs": {
                "hosts": {
                    "terms": {
                        "field": "host",
                        "size": 100
                    }
                }
            }
        }
        
        result = await es.search(index=index, body=body)
        
        buckets = result.get("aggregations", {}).get("hosts", {}).get("buckets", [])
        
        return {
            "hours": hours,
            "hosts": [
                {"hostname": b["key"], "log_count": b["doc_count"]}
                for b in buckets
            ]
        }
        
    except Exception as e:
        logger.warning("Active hosts query failed", error=str(e))
        return {"hours": hours, "hosts": []}
