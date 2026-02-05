"""
SecureSight Backend - Main Application
Real-time SIEM & Threat Detection Platform
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
import structlog

from app.core.config import settings
from app.core.logging import setup_logging
from app.api.v1.router import api_router
from app.core.database import init_db
from app.core.elasticsearch import init_elasticsearch
from app.core.redis import init_redis

# Setup structured logging
setup_logging()
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting SecureSight Backend", version=settings.APP_VERSION)
    
    # Initialize database
    await init_db()
    logger.info("Database initialized")
    
    # Initialize Elasticsearch
    await init_elasticsearch()
    logger.info("Elasticsearch initialized")
    
    # Initialize Redis
    await init_redis()
    logger.info("Redis initialized")
    
    yield
    
    # Shutdown
    logger.info("Shutting down SecureSight Backend")


# Create FastAPI application
app = FastAPI(
    title="SecureSight API",
    description="Real-time SIEM & Threat Detection Platform API",
    version=settings.APP_VERSION,
    docs_url="/api/docs" if settings.APP_DEBUG else None,
    redoc_url="/api/redoc" if settings.APP_DEBUG else None,
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip Middleware for response compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Include API routes
app.include_router(api_router, prefix="/api/v1")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "service": "securesight-backend"
    }


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Welcome to SecureSight API",
        "docs": "/api/docs",
        "version": settings.APP_VERSION
    }
