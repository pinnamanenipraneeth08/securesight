"""
WebSocket endpoints for real-time updates
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from app.core.websocket import manager
from app.core.security import decode_token
import structlog

logger = structlog.get_logger()
router = APIRouter()


async def get_current_user_ws(token: str) -> dict | None:
    """Verify WebSocket authentication token"""
    try:
        payload = decode_token(token)
        if payload and payload.type == "access":
            return {"user_id": payload.sub, "roles": payload.roles}
    except Exception as e:
        logger.warning("WebSocket auth failed", error=str(e))
    return None


@router.websocket("/ws/{channel}")
async def websocket_endpoint(
    websocket: WebSocket,
    channel: str,
    token: str = Query(None)
):
    """
    WebSocket endpoint for real-time updates.
    
    Channels:
    - alerts: New alert notifications
    - events: New security events
    - logs: Log stream
    - dashboard: Dashboard stats updates
    
    Query params:
    - token: JWT access token for authentication
    """
    # Validate channel
    valid_channels = ["alerts", "events", "logs", "dashboard"]
    if channel not in valid_channels:
        await websocket.close(code=4000, reason=f"Invalid channel. Use: {valid_channels}")
        return
    
    # Authenticate
    if token:
        user = await get_current_user_ws(token)
        if not user:
            await websocket.close(code=4001, reason="Invalid or expired token")
            return
    else:
        # Allow unauthenticated for now (can be changed to require auth)
        user = None
    
    # Connect
    await manager.connect(websocket, channel)
    
    try:
        # Send initial connection confirmation
        await manager.send_personal_message({
            "type": "connected",
            "channel": channel,
            "message": f"Connected to {channel} channel"
        }, websocket)
        
        # Keep connection alive and listen for client messages
        while True:
            data = await websocket.receive_text()
            
            # Handle ping/pong for keep-alive
            if data == "ping":
                await manager.send_personal_message({"type": "pong"}, websocket)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)
        logger.info("WebSocket client disconnected", channel=channel)
    except Exception as e:
        logger.error("WebSocket error", channel=channel, error=str(e))
        manager.disconnect(websocket, channel)


@router.get("/ws/status")
async def websocket_status():
    """Get WebSocket connection statistics"""
    return {
        "total_connections": manager.get_connection_count(),
        "channels": {
            "alerts": manager.get_connection_count("alerts"),
            "events": manager.get_connection_count("events"),
            "logs": manager.get_connection_count("logs"),
            "dashboard": manager.get_connection_count("dashboard"),
        }
    }
