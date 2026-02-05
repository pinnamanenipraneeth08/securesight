"""
SecureSight - Log Processor Service

Processes logs from the queue and stores them in Elasticsearch.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
import orjson
import structlog

from app.core.redis import LogQueue
from app.core.elasticsearch import get_elasticsearch
from app.core.config import settings

logger = structlog.get_logger()


class LogProcessor:
    """Log processor class for processing and indexing logs"""
    
    def __init__(self):
        self.es = get_elasticsearch()
    
    async def process_batch(self, logs: List[str]) -> Dict[str, Any]:
        """
        Process a batch of raw log strings.
        
        Args:
            logs: List of JSON-encoded log strings
            
        Returns:
            Dict with 'indexed' count and any errors
        """
        if not logs:
            return {"indexed": 0, "errors": 0}
        
        logger.info("Processing log batch", count=len(logs))
        
        # Parse and normalize logs
        normalized_logs = []
        parse_errors = 0
        for log_json in logs:
            try:
                log = orjson.loads(log_json)
                normalized = normalize_log(log)
                normalized_logs.append(normalized)
            except Exception as e:
                parse_errors += 1
                logger.warning("Failed to parse log", error=str(e))
        
        if not normalized_logs:
            return {"indexed": 0, "errors": parse_errors}
        
        # Index in Elasticsearch
        today = datetime.utcnow().strftime("%Y.%m.%d")
        index = f"{settings.ELASTICSEARCH_INDEX_PREFIX}-logs-{today}"
        
        # Bulk index
        bulk_body = []
        for log in normalized_logs:
            bulk_body.append({"index": {"_index": index}})
            bulk_body.append(log)
        
        try:
            result = await self.es.bulk(body=bulk_body, refresh=False)
            
            if result.get("errors"):
                error_count = sum(1 for item in result["items"] if "error" in item.get("index", {}))
                logger.warning("Bulk indexing had errors", error_count=error_count)
            else:
                error_count = 0
            
            indexed_count = len([item for item in result["items"] if "error" not in item.get("index", {})])
            logger.info("Logs indexed", count=indexed_count, index=index)
            
            # Broadcast logs via WebSocket for real-time updates
            try:
                from app.core.websocket import manager
                # Only broadcast a sample to avoid flooding
                for log in normalized_logs[:10]:  # Limit to 10 logs per batch
                    await manager.broadcast_log({
                        "host": log.get("host"),
                        "source": log.get("source"),
                        "event_type": log.get("event_type"),
                        "severity": log.get("severity"),
                        "message": log.get("message", "")[:200],  # Truncate message
                        "timestamp": log.get("timestamp"),
                    })
            except Exception as e:
                logger.warning("Failed to broadcast logs via WebSocket", error=str(e))
            
            # Trigger detection engine
            from app.services.detection_engine import process_logs_for_detection
            await process_logs_for_detection(normalized_logs)
            
            return {"indexed": indexed_count, "errors": parse_errors + error_count}
            
        except Exception as e:
            logger.error("Bulk indexing failed", error=str(e))
            return {"indexed": 0, "errors": len(logs)}


async def process_logs_batch(batch_size: Optional[int] = None):
    """
    Process a batch of logs from the queue.
    
    - Pulls logs from Redis queue
    - Normalizes and enriches log data
    - Indexes logs in Elasticsearch
    - Triggers detection engine
    """
    batch_size = batch_size or settings.AGENT_BATCH_SIZE
    queue = LogQueue()
    es = get_elasticsearch()
    
    # Get batch from queue
    logs = await queue.pop(batch_size)
    
    if not logs:
        return 0
    
    logger.info("Processing log batch", count=len(logs))
    
    # Parse and normalize logs
    normalized_logs = []
    for log_json in logs:
        try:
            log = orjson.loads(log_json)
            normalized = normalize_log(log)
            normalized_logs.append(normalized)
        except Exception as e:
            logger.warning("Failed to parse log", error=str(e))
    
    if not normalized_logs:
        return 0
    
    # Index in Elasticsearch
    today = datetime.utcnow().strftime("%Y.%m.%d")
    index = f"{settings.ELASTICSEARCH_INDEX_PREFIX}-logs-{today}"
    
    # Bulk index
    bulk_body = []
    for log in normalized_logs:
        bulk_body.append({"index": {"_index": index}})
        bulk_body.append(log)
    
    try:
        result = await es.bulk(body=bulk_body, refresh=False)
        
        if result.get("errors"):
            error_count = sum(1 for item in result["items"] if "error" in item.get("index", {}))
            logger.warning("Bulk indexing had errors", error_count=error_count)
        
        indexed_count = len([item for item in result["items"] if "error" not in item.get("index", {})])
        logger.info("Logs indexed", count=indexed_count, index=index)
        
        # Trigger detection engine
        from app.services.detection_engine import process_logs_for_detection
        await process_logs_for_detection(normalized_logs)
        
        return indexed_count
        
    except Exception as e:
        logger.error("Bulk indexing failed", error=str(e))
        return 0


def normalize_log(log: dict) -> dict:
    """
    Normalize log to standard schema.
    
    Standard schema:
    {
        "timestamp": ISO datetime,
        "source": log source type,
        "host": hostname/IP,
        "event_type": categorized event type,
        "message": log message,
        "severity": normalized severity,
        "raw": original message,
        "parsed": extracted fields,
        "tags": list of tags,
        "user": {name, id, domain},
        "network": {src_ip, dst_ip, src_port, dst_port, protocol},
        "process": {name, pid, command},
        "geo": {ip, country, city, location}
    }
    """
    normalized = {
        "timestamp": log.get("timestamp") or datetime.utcnow().isoformat(),
        "source": log.get("source", "unknown"),
        "host": log.get("host", "unknown"),
        "event_type": categorize_event(log),
        "message": log.get("message", ""),
        "severity": normalize_severity(log.get("severity", "info")),
        "raw": log.get("raw", log.get("message", "")),
        "parsed": log.get("parsed", {}),
        "tags": log.get("tags", []),
    }
    
    # Include optional fields if present
    if log.get("user"):
        normalized["user"] = log["user"]
    
    if log.get("network"):
        normalized["network"] = log["network"]
    
    if log.get("process"):
        normalized["process"] = log["process"]
    
    if log.get("geo"):
        normalized["geo"] = log["geo"]
    
    # Add processing metadata
    normalized["_processed_at"] = datetime.utcnow().isoformat()
    
    return normalized


def categorize_event(log: dict) -> str:
    """Categorize event based on log content"""
    event_type = log.get("event_type", "")
    if event_type:
        return event_type
    
    message = log.get("message", "").lower()
    source = log.get("source", "").lower()
    
    # Authentication events
    if any(word in message for word in ["login", "logon", "authenticate"]):
        if any(word in message for word in ["fail", "invalid", "denied"]):
            return "auth_failure"
        elif any(word in message for word in ["success", "accepted"]):
            return "auth_success"
        return "auth_attempt"
    
    # Security events
    if any(word in message for word in ["attack", "exploit", "malware", "virus"]):
        return "security_alert"
    
    if any(word in message for word in ["permission denied", "access denied", "unauthorized"]):
        return "access_denied"
    
    # Network events
    if any(word in message for word in ["connection", "connect", "disconnect"]):
        return "network_connection"
    
    if any(word in message for word in ["firewall", "blocked", "dropped"]):
        return "firewall_event"
    
    # System events
    if any(word in message for word in ["start", "stop", "restart", "shutdown"]):
        return "system_event"
    
    if any(word in message for word in ["error", "exception", "crash"]):
        return "error"
    
    if any(word in message for word in ["warning", "warn"]):
        return "warning"
    
    return "other"


def normalize_severity(severity: str) -> str:
    """Normalize severity to standard levels"""
    severity = str(severity).lower().strip()
    
    severity_map = {
        # Critical
        "critical": "critical",
        "crit": "critical",
        "fatal": "critical",
        "emergency": "critical",
        "emerg": "critical",
        "0": "critical",
        "1": "critical",
        
        # High
        "high": "high",
        "error": "high",
        "err": "high",
        "alert": "high",
        "2": "high",
        "3": "high",
        
        # Medium
        "medium": "medium",
        "warning": "medium",
        "warn": "medium",
        "4": "medium",
        
        # Low
        "low": "low",
        "notice": "low",
        "5": "low",
        
        # Info
        "info": "info",
        "informational": "info",
        "6": "info",
        
        # Debug
        "debug": "debug",
        "7": "debug",
    }
    
    return severity_map.get(severity, "info")


async def process_continuously():
    """
    Continuous log processing loop.
    
    Run this as a background task.
    """
    import asyncio
    
    logger.info("Starting continuous log processor")
    
    while True:
        try:
            processed = await process_logs_batch()
            
            if processed == 0:
                # No logs to process, wait a bit
                await asyncio.sleep(1)
            else:
                # Processed some logs, continue immediately
                await asyncio.sleep(0.1)
                
        except Exception as e:
            logger.error("Log processing error", error=str(e))
            await asyncio.sleep(5)
