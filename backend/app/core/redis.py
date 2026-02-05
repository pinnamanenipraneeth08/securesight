"""
SecureSight - Redis Configuration
"""

import redis.asyncio as redis
from typing import Optional
import structlog

from app.core.config import settings

logger = structlog.get_logger()

# Global Redis client
redis_client: Optional[redis.Redis] = None


def get_redis() -> redis.Redis:
    """Get Redis client instance"""
    global redis_client
    if redis_client is None:
        redis_client = redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
    return redis_client


async def init_redis():
    """Initialize Redis connection"""
    client = get_redis()
    try:
        await client.ping()
        logger.info("Redis connected")
    except Exception as e:
        logger.warning("Redis connection failed", error=str(e))


async def close_redis():
    """Close Redis connection"""
    global redis_client
    if redis_client:
        await redis_client.close()
        redis_client = None


class LogQueue:
    """Log queue for buffering incoming logs before processing"""
    
    QUEUE_KEY = "securesight:log_queue"
    PROCESSING_KEY = "securesight:log_processing"
    
    def __init__(self, client: redis.Redis = None):
        self.client = client or get_redis()
    
    async def push(self, log_data: str) -> int:
        """Push log to queue"""
        return await self.client.lpush(self.QUEUE_KEY, log_data)
    
    async def push_batch(self, logs: list[str]) -> int:
        """Push multiple logs to queue"""
        if not logs:
            return 0
        return await self.client.lpush(self.QUEUE_KEY, *logs)
    
    async def pop(self, count: int = 1) -> list[str]:
        """Pop logs from queue"""
        logs = []
        for _ in range(count):
            log = await self.client.rpop(self.QUEUE_KEY)
            if log:
                logs.append(log)
            else:
                break
        return logs
    
    async def pop_batch(self, count: int = 100) -> list[str]:
        """Pop a batch of logs from queue (alias for pop)"""
        return await self.pop(count)
    
    async def length(self) -> int:
        """Get queue length"""
        return await self.client.llen(self.QUEUE_KEY)


async def get_log_queue() -> LogQueue:
    """Get LogQueue instance (worker compatibility)"""
    return LogQueue()


class RateLimiter:
    """Rate limiter using Redis"""
    
    def __init__(self, client: Optional[redis.Redis] = None):
        self.client = client or get_redis()
    
    async def is_allowed(
        self,
        key: str,
        max_requests: Optional[int] = None,
        window_seconds: Optional[int] = None
    ) -> bool:
        """Check if request is allowed under rate limit"""
        max_requests = max_requests or settings.RATE_LIMIT_REQUESTS
        window_seconds = window_seconds or settings.RATE_LIMIT_WINDOW
        
        rate_key = f"securesight:ratelimit:{key}"
        
        pipe = self.client.pipeline()
        pipe.incr(rate_key)
        pipe.expire(rate_key, window_seconds)
        
        results = await pipe.execute()
        current_count = results[0]
        
        return current_count <= max_requests
    
    async def get_remaining(self, key: str, max_requests: Optional[int] = None) -> int:
        """Get remaining requests for a key"""
        max_requests = max_requests or settings.RATE_LIMIT_REQUESTS
        rate_key = f"securesight:ratelimit:{key}"
        
        current = await self.client.get(rate_key)
        if current is None:
            return max_requests
        return max(0, max_requests - int(current))
