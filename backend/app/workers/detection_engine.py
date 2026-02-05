"""
Detection Engine Worker

Continuously evaluates logs against detection rules and generates alerts.
"""

import asyncio
import signal
import logging
from datetime import datetime, timedelta, timezone

import structlog

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = structlog.get_logger(__name__)


class DetectionEngineWorker:
    """Worker that runs detection rules against incoming logs"""
    
    def __init__(self):
        self.running = True
        self.batch_size = 100
        self.process_interval = 2.0  # seconds
        self.last_check = datetime.now(timezone.utc) - timedelta(minutes=5)
    
    async def setup(self):
        """Initialize connections"""
        from app.core.elasticsearch import init_elasticsearch
        from app.core.database import init_db
        
        # Initialize database
        await init_db()
        logger.info("Database initialized")
        
        # Initialize Elasticsearch
        await init_elasticsearch()
        logger.info("Elasticsearch initialized")
    
    async def get_active_rules(self):
        """Get all active detection rules"""
        from app.core.database import get_session
        from app.models.rule import Rule
        from sqlalchemy import select
        
        async with get_session() as session:
            result = await session.execute(
                select(Rule).where(Rule.is_enabled == True)
            )
            return result.scalars().all()
    
    async def get_recent_logs(self, since: datetime):
        """Get logs since the last check"""
        from app.core.elasticsearch import get_es_client
        from app.core.config import settings
        
        client = await get_es_client()
        
        query = {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": since.isoformat(),
                                "lte": datetime.now(timezone.utc).isoformat()
                            }
                        }
                    }
                ]
            }
        }
        
        response = await client.search(
            index=f"{settings.ELASTICSEARCH_INDEX_PREFIX}-logs-*",
            query=query,
            size=self.batch_size,
            sort=[{"timestamp": "asc"}]
        )
        
        return [hit["_source"] for hit in response["hits"]["hits"]]
    
    async def run_detection(self):
        """Run detection on recent logs"""
        from app.services.detection_engine import DetectionEngine
        from app.core.database import get_session
        
        # Get active rules
        rules = await self.get_active_rules()
        if not rules:
            return 0
        
        # Get recent logs
        logs = await self.get_recent_logs(self.last_check)
        if not logs:
            return 0
        
        # Update last check time
        self.last_check = datetime.now(timezone.utc)
        
        # Run detection
        async with get_session() as session:
            engine = DetectionEngine(session)
            alerts = []
            
            for log in logs:
                for rule in rules:
                    alert = await engine.evaluate_rule(rule, log)
                    if alert:
                        alerts.append(alert)
            
            if alerts:
                logger.info(
                    "Detection complete",
                    logs_checked=len(logs),
                    rules_evaluated=len(rules),
                    alerts_generated=len(alerts),
                )
            
            return len(alerts)
    
    async def run(self):
        """Main worker loop"""
        logger.info("Starting Detection Engine Worker")
        
        await self.setup()
        
        while self.running:
            try:
                alerts = await self.run_detection()
                
                # Wait before next check
                await asyncio.sleep(self.process_interval)
                
            except Exception as e:
                logger.error("Worker error", error=str(e))
                await asyncio.sleep(5)
        
        logger.info("Detection Engine Worker stopped")
    
    def stop(self):
        """Stop the worker"""
        self.running = False


async def main():
    worker = DetectionEngineWorker()
    
    # Handle shutdown signals
    def signal_handler(sig, frame):
        logger.info("Shutdown signal received")
        worker.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
