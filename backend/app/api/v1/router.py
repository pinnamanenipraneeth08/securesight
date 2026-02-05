"""
SecureSight - API v1 Router
"""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth,
    users,
    logs,
    alerts,
    rules,
    incidents,
    dashboard,
    health,
    websocket,
)

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(logs.router, prefix="/logs", tags=["Log Ingestion"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])
api_router.include_router(rules.router, prefix="/rules", tags=["Detection Rules"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(health.router, prefix="/health", tags=["Health"])
api_router.include_router(websocket.router, tags=["WebSocket"])
