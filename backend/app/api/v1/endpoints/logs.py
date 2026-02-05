"""
SecureSight - Log Ingestion API Endpoints
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel, Field, validator
import structlog
import orjson
import hashlib

from app.core.security import verify_agent_api_key
from app.core.redis import LogQueue, RateLimiter, get_redis
from app.core.elasticsearch import get_elasticsearch
from app.core.config import settings
from app.services.log_processor import process_logs_batch

logger = structlog.get_logger()
router = APIRouter()


class LogEvent(BaseModel):
    """Single log event schema"""
    timestamp: Optional[datetime] = None
    source: str = Field(..., description="Log source (e.g., 'syslog', 'windows_event')")
    host: str = Field(..., description="Hostname or IP")
    event_type: str = Field(..., description="Type of event (e.g., 'auth_failure')")
    message: str = Field(..., description="Log message")
    severity: Optional[str] = Field(default="info", description="Log severity level")
    
    # Optional fields
    raw: Optional[str] = None
    parsed: Optional[dict] = None
    tags: Optional[List[str]] = None
    
    # User context
    user: Optional[dict] = None
    
    # Network context
    network: Optional[dict] = None
    
    # Process context
    process: Optional[dict] = None
    
    @validator("timestamp", pre=True, always=True)
    def default_timestamp(cls, v):
        return v or datetime.utcnow()
    
    @validator("severity")
    def normalize_severity(cls, v):
        valid = ["critical", "high", "medium", "low", "info", "debug"]
        v = v.lower() if v else "info"
        return v if v in valid else "info"


class BulkLogRequest(BaseModel):
    """Bulk log ingestion request"""
    events: List[LogEvent] = Field(..., min_length=1, max_length=1000)


class LogIngestionResponse(BaseModel):
    """Response for log ingestion"""
    status: str
    accepted: int
    queued: int
    message: str = ""


@router.post("/ingest", response_model=LogIngestionResponse)
async def ingest_single_log(
    log: LogEvent,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_agent_api_key),
):
    """
    Ingest a single log event.
    
    Requires API key authentication.
    """
    rate_limiter = RateLimiter()
    
    # Rate limiting by API key
    if not await rate_limiter.is_allowed(f"ingest:{api_key}"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )
    
    try:
        # Queue the log for processing
        queue = LogQueue()
        log_json = orjson.dumps(log.model_dump(mode="json")).decode()
        await queue.push(log_json)
        
        logger.info("Log ingested", host=log.host, source=log.source)
        
        return LogIngestionResponse(
            status="success",
            accepted=1,
            queued=1,
            message="Log accepted for processing"
        )
        
    except Exception as e:
        logger.error("Log ingestion failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to ingest log"
        )


@router.post("/ingest/bulk", response_model=LogIngestionResponse)
async def ingest_bulk_logs(
    request: BulkLogRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_agent_api_key),
):
    """
    Ingest multiple log events in bulk.
    
    - Maximum 1000 events per request
    - Requires API key authentication
    - Events are queued for async processing
    """
    rate_limiter = RateLimiter()
    
    # Rate limiting
    if not await rate_limiter.is_allowed(f"ingest:{api_key}"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )
    
    try:
        queue = LogQueue()
        
        # Convert all logs to JSON
        log_jsons = [
            orjson.dumps(log.model_dump(mode="json")).decode()
            for log in request.events
        ]
        
        # Push all logs to queue
        await queue.push_batch(log_jsons)
        
        count = len(request.events)
        logger.info("Bulk logs ingested", count=count)
        
        # Trigger background processing if queue is large
        queue_length = await queue.length()
        if queue_length >= settings.AGENT_BATCH_SIZE:
            background_tasks.add_task(process_logs_batch)
        
        return LogIngestionResponse(
            status="success",
            accepted=count,
            queued=count,
            message=f"{count} logs accepted for processing"
        )
        
    except Exception as e:
        logger.error("Bulk ingestion failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to ingest logs"
        )


@router.get("/search")
async def search_logs(
    query: Optional[str] = None,
    host: Optional[str] = None,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 100,
    offset: int = 0,
    api_key: str = Depends(verify_agent_api_key),
):
    """
    Search logs in Elasticsearch.
    
    Supports filtering by various fields and time range.
    """
    es = get_elasticsearch()
    index = f"{settings.ELASTICSEARCH_INDEX_PREFIX}-logs-*"
    
    # Build query
    must = []
    
    if query:
        must.append({"multi_match": {"query": query, "fields": ["message", "raw"]}})
    
    if host:
        must.append({"term": {"host": host}})
    
    if source:
        must.append({"term": {"source": source}})
    
    if severity:
        must.append({"term": {"severity": severity}})
    
    if event_type:
        must.append({"term": {"event_type": event_type}})
    
    # Time range filter
    time_range = {}
    if start_time:
        time_range["gte"] = start_time.isoformat()
    if end_time:
        time_range["lte"] = end_time.isoformat()
    if time_range:
        must.append({"range": {"timestamp": time_range}})
    
    # Execute search
    try:
        body = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "from": offset,
            "size": min(limit, 1000),
        }
        
        result = await es.search(index=index, body=body)
        
        hits = result["hits"]["hits"]
        total = result["hits"]["total"]["value"]
        
        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "logs": [hit["_source"] for hit in hits]
        }
        
    except Exception as e:
        logger.error("Log search failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Search failed"
        )


@router.get("/stats")
async def get_log_stats(
    api_key: str = Depends(verify_agent_api_key),
):
    """Get log ingestion statistics"""
    queue = LogQueue()
    queue_length = await queue.length()
    
    es = get_elasticsearch()
    
    try:
        # Get index stats
        index = f"{settings.ELASTICSEARCH_INDEX_PREFIX}-logs-*"
        stats = await es.indices.stats(index=index)
        
        total_docs = stats["_all"]["total"]["docs"]["count"]
        total_size = stats["_all"]["total"]["store"]["size_in_bytes"]
        
        return {
            "queue_length": queue_length,
            "total_logs": total_docs,
            "storage_bytes": total_size,
            "storage_human": f"{total_size / (1024**3):.2f} GB"
        }
        
    except Exception as e:
        logger.warning("Stats retrieval failed", error=str(e))
        return {
            "queue_length": queue_length,
            "total_logs": 0,
            "storage_bytes": 0,
            "storage_human": "N/A"
        }
