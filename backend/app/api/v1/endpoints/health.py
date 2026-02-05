"""
SecureSight - Health Check Endpoints
"""

from fastapi import APIRouter
import structlog

from app.core.config import settings
from app.core.elasticsearch import get_elasticsearch
from app.core.redis import get_redis

logger = structlog.get_logger()
router = APIRouter()


@router.get("/")
async def health_check():
    """Basic health check"""
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
    }


@router.get("/detailed")
async def detailed_health():
    """Detailed health check with service status"""
    services = {
        "api": {"status": "healthy"},
        "database": {"status": "unknown"},
        "elasticsearch": {"status": "unknown"},
        "redis": {"status": "unknown"},
    }
    
    # Check Elasticsearch
    try:
        es = get_elasticsearch()
        info = await es.info()
        services["elasticsearch"] = {
            "status": "healthy",
            "version": info["version"]["number"],
        }
    except Exception as e:
        services["elasticsearch"] = {
            "status": "unhealthy",
            "error": str(e),
        }
    
    # Check Redis
    try:
        redis = get_redis()
        await redis.ping()
        services["redis"] = {"status": "healthy"}
    except Exception as e:
        services["redis"] = {
            "status": "unhealthy",
            "error": str(e),
        }
    
    # Check Database (via simple query)
    try:
        from sqlalchemy import text
        from app.core.database import async_session_factory
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
            services["database"] = {"status": "healthy"}
    except Exception as e:
        services["database"] = {
            "status": "unhealthy",
            "error": str(e),
        }
    
    # Overall status
    all_healthy = all(s["status"] == "healthy" for s in services.values())
    
    return {
        "status": "healthy" if all_healthy else "degraded",
        "version": settings.APP_VERSION,
        "services": services,
    }


@router.get("/ready")
async def readiness_check():
    """Kubernetes readiness probe"""
    try:
        # Check critical services
        es = get_elasticsearch()
        await es.info()
        
        redis = get_redis()
        await redis.ping()
        
        return {"status": "ready"}
    except Exception as e:
        return {"status": "not_ready", "error": str(e)}


@router.get("/live")
async def liveness_check():
    """Kubernetes liveness probe"""
    return {"status": "alive"}
