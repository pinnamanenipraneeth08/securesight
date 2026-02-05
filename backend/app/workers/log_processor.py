"""
Log Processor Worker

Continuously processes logs from the Redis queue and indexes them into Elasticsearch.
"""

import asyncio
import signal
import logging
from contextlib import asynccontextmanager

import structlog

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = structlog.get_logger(__name__)


class LogProcessorWorker:
    """Worker that processes logs from Redis queue"""
    
    def __init__(self):
        self.running = True
        self.batch_size = 100
        self.process_interval = 1.0  # seconds
    
    async def setup(self):
        """Initialize connections"""
        from app.core.elasticsearch import init_elasticsearch, get_es_client
        from app.core.redis import get_redis
        
        # Initialize Elasticsearch
        await init_elasticsearch()
        logger.info("Elasticsearch initialized")
        
        # Verify Redis connection
        redis = await get_redis()
        await redis.ping()
        logger.info("Redis connection verified")
    
    async def process_batch(self):
        """Process a batch of logs from the queue"""
        from app.core.redis import get_log_queue
        from app.services.log_processor import LogProcessor
        
        queue = await get_log_queue()
        processor = LogProcessor()
        
        # Get batch of logs
        logs = await queue.pop_batch(self.batch_size)
        
        if not logs:
            return 0
        
        # Process logs
        try:
            result = await processor.process_batch(logs)
            logger.info(
                "Processed log batch",
                count=len(logs),
                indexed=result.get("indexed", 0),
            )
            return len(logs)
        except Exception as e:
            logger.error("Failed to process batch", error=str(e))
            # Re-queue failed logs
            for log in logs:
                await queue.push(log)
            return 0
    
    async def run(self):
        """Main worker loop"""
        logger.info("Starting Log Processor Worker")
        
        await self.setup()
        
        while self.running:
            try:
                processed = await self.process_batch()
                
                # If no logs were processed, wait a bit
                if processed == 0:
                    await asyncio.sleep(self.process_interval)
                    
            except Exception as e:
                logger.error("Worker error", error=str(e))
                await asyncio.sleep(5)
        
        logger.info("Log Processor Worker stopped")
    
    def stop(self):
        """Stop the worker"""
        self.running = False


async def main():
    worker = LogProcessorWorker()
    
    # Handle shutdown signals
    def signal_handler(sig, frame):
        logger.info("Shutdown signal received")
        worker.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
