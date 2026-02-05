"""
WebSocket Connection Manager for Real-time Updates
"""

from typing import Dict, List, Set
from fastapi import WebSocket
import structlog
import json
from datetime import datetime

logger = structlog.get_logger()


class ConnectionManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self):
        # Store active connections by channel
        self.active_connections: Dict[str, Set[WebSocket]] = {
            "alerts": set(),
            "events": set(),
            "logs": set(),
            "dashboard": set(),
        }
    
    async def connect(self, websocket: WebSocket, channel: str = "alerts"):
        """Accept a new WebSocket connection"""
        await websocket.accept()
        if channel not in self.active_connections:
            self.active_connections[channel] = set()
        self.active_connections[channel].add(websocket)
        logger.info("WebSocket connected", channel=channel, total=len(self.active_connections[channel]))
    
    def disconnect(self, websocket: WebSocket, channel: str = "alerts"):
        """Remove a WebSocket connection"""
        if channel in self.active_connections:
            self.active_connections[channel].discard(websocket)
            logger.info("WebSocket disconnected", channel=channel, remaining=len(self.active_connections[channel]))
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send message to a specific connection"""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error("Failed to send WebSocket message", error=str(e))
    
    async def broadcast(self, channel: str, message: dict):
        """Broadcast message to all connections in a channel"""
        if channel not in self.active_connections:
            return
        
        disconnected = set()
        for connection in self.active_connections[channel]:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning("WebSocket send failed, marking for disconnect", error=str(e))
                disconnected.add(connection)
        
        # Remove disconnected clients
        for connection in disconnected:
            self.active_connections[channel].discard(connection)
    
    async def broadcast_alert(self, alert: dict):
        """Broadcast a new alert to all alert subscribers"""
        message = {
            "type": "new_alert",
            "timestamp": datetime.utcnow().isoformat(),
            "data": alert
        }
        await self.broadcast("alerts", message)
        await self.broadcast("dashboard", message)  # Also update dashboard
    
    async def broadcast_event(self, event: dict):
        """Broadcast a new event to all event subscribers"""
        message = {
            "type": "new_event",
            "timestamp": datetime.utcnow().isoformat(),
            "data": event
        }
        await self.broadcast("events", message)
    
    async def broadcast_log(self, log: dict):
        """Broadcast a new log entry"""
        message = {
            "type": "new_log",
            "timestamp": datetime.utcnow().isoformat(),
            "data": log
        }
        await self.broadcast("logs", message)
    
    async def broadcast_stats_update(self, stats: dict):
        """Broadcast dashboard stats update"""
        message = {
            "type": "stats_update",
            "timestamp": datetime.utcnow().isoformat(),
            "data": stats
        }
        await self.broadcast("dashboard", message)
    
    def get_connection_count(self, channel: str = None) -> int:
        """Get the number of active connections"""
        if channel:
            return len(self.active_connections.get(channel, set()))
        return sum(len(conns) for conns in self.active_connections.values())


# Global connection manager instance
manager = ConnectionManager()
