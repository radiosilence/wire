from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Set

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


@dataclass
class Connection:
    """Represents a WebSocket connection."""
    
    websocket: WebSocket
    user_id: str
    connected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_ping: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


class ConnectionManager:
    """Manages WebSocket connections for real-time messaging."""
    
    def __init__(self) -> None:
        # User ID -> Set of connections (multiple devices support)
        self._connections: dict[str, set[Connection]] = defaultdict(set)
        
        # Connection -> User ID mapping for fast lookup
        self._connection_to_user: dict[WebSocket, str] = {}
        
        # User presence status
        self._presence: dict[str, str] = {}
        
        # Locks for thread safety
        self._lock = asyncio.Lock()
        
        # Background tasks
        self._tasks: set[asyncio.Task] = set()
    
    async def connect(self, user_id: str, websocket: WebSocket) -> Connection:
        """Add a new connection."""
        async with self._lock:
            connection = Connection(websocket=websocket, user_id=user_id)
            self._connections[user_id].add(connection)
            self._connection_to_user[websocket] = user_id
            self._presence[user_id] = "online"
            
            logger.info(f"User {user_id} connected. Total connections: {len(self._connections[user_id])}")
            
            # Notify contacts about online status
            asyncio.create_task(self._notify_presence_change(user_id, "online"))
            
            return connection
    
    async def disconnect(self, user_id: str, websocket: WebSocket | None = None) -> None:
        """Remove a connection."""
        async with self._lock:
            if user_id not in self._connections:
                return
            
            if websocket:
                # Remove specific connection
                self._connections[user_id] = {
                    conn for conn in self._connections[user_id]
                    if conn.websocket != websocket
                }
                self._connection_to_user.pop(websocket, None)
            else:
                # Remove all connections for user
                for conn in self._connections[user_id]:
                    self._connection_to_user.pop(conn.websocket, None)
                self._connections[user_id].clear()
            
            # Update presence if no more connections
            if not self._connections[user_id]:
                del self._connections[user_id]
                self._presence[user_id] = "offline"
                
                logger.info(f"User {user_id} disconnected completely")
                
                # Notify contacts about offline status
                asyncio.create_task(self._notify_presence_change(user_id, "offline"))
    
    async def disconnect_all(self) -> None:
        """Disconnect all connections gracefully."""
        async with self._lock:
            for user_id, connections in list(self._connections.items()):
                for conn in connections:
                    try:
                        await conn.websocket.close()
                    except Exception as e:
                        logger.error(f"Error closing connection for {user_id}: {e}")
            
            self._connections.clear()
            self._connection_to_user.clear()
            self._presence.clear()
        
        # Cancel all background tasks
        for task in self._tasks:
            task.cancel()
        
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        
        self._tasks.clear()
    
    async def send_to_user(self, user_id: str, message: dict[str, Any]) -> int:
        """Send message to all connections of a user."""
        if user_id not in self._connections:
            return 0
        
        sent_count = 0
        failed_connections = []
        
        for connection in self._connections[user_id]:
            try:
                await connection.websocket.send_json(message)
                sent_count += 1
            except WebSocketDisconnect:
                failed_connections.append(connection.websocket)
            except Exception as e:
                logger.error(f"Error sending to {user_id}: {e}")
                failed_connections.append(connection.websocket)
        
        # Clean up failed connections
        for websocket in failed_connections:
            await self.disconnect(user_id, websocket)
        
        return sent_count
    
    async def broadcast_to_users(self, user_ids: set[str], message: dict[str, Any]) -> dict[str, int]:
        """Broadcast message to multiple users."""
        results = {}
        
        tasks = []
        for user_id in user_ids:
            if user_id in self._connections:
                tasks.append(self.send_to_user(user_id, message))
        
        if tasks:
            sent_counts = await asyncio.gather(*tasks)
            for user_id, count in zip(user_ids, sent_counts):
                results[user_id] = count
        
        return results
    
    async def send_to_room(self, room_id: str, message: dict[str, Any], exclude_user: str | None = None) -> int:
        """Send message to all users in a room/channel."""
        # This would integrate with a room membership system
        # For now, just a placeholder
        room_members = await self._get_room_members(room_id)
        
        if exclude_user:
            room_members.discard(exclude_user)
        
        results = await self.broadcast_to_users(room_members, message)
        return sum(results.values())
    
    async def update_presence(self, user_id: str, status: str) -> None:
        """Update user presence status."""
        old_status = self._presence.get(user_id, "offline")
        
        if old_status != status:
            self._presence[user_id] = status
            await self._notify_presence_change(user_id, status)
    
    def get_presence(self, user_id: str) -> str:
        """Get user presence status."""
        return self._presence.get(user_id, "offline")
    
    def get_online_users(self) -> set[str]:
        """Get all online users."""
        return {user_id for user_id, status in self._presence.items() if status == "online"}
    
    def get_user_connections(self, user_id: str) -> int:
        """Get number of active connections for a user."""
        return len(self._connections.get(user_id, set()))
    
    def is_online(self, user_id: str) -> bool:
        """Check if user is online."""
        return user_id in self._connections and len(self._connections[user_id]) > 0
    
    async def ping_connections(self) -> None:
        """Ping all connections to keep them alive."""
        ping_message = {"type": "ping", "timestamp": datetime.now(timezone.utc).isoformat()}
        
        for user_id, connections in list(self._connections.items()):
            failed_connections = []
            
            for connection in connections:
                try:
                    await connection.websocket.send_json(ping_message)
                    connection.last_ping = datetime.now(timezone.utc)
                except Exception:
                    failed_connections.append(connection.websocket)
            
            # Clean up failed connections
            for websocket in failed_connections:
                await self.disconnect(user_id, websocket)
    
    async def start_ping_task(self, interval: int = 30) -> None:
        """Start background task to ping connections."""
        async def ping_loop():
            while True:
                try:
                    await asyncio.sleep(interval)
                    await self.ping_connections()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in ping task: {e}")
        
        task = asyncio.create_task(ping_loop())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
    
    async def _notify_presence_change(self, user_id: str, status: str) -> None:
        """Notify user's contacts about presence change."""
        # Get user's contacts (this would integrate with the contacts system)
        contacts = await self._get_user_contacts(user_id)
        
        message = {
            "type": "presence",
            "user_id": user_id,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        # Only notify online contacts
        online_contacts = contacts & self.get_online_users()
        await self.broadcast_to_users(online_contacts, message)
    
    async def _get_user_contacts(self, user_id: str) -> set[str]:
        """Get user's contacts from Redis."""
        # Placeholder - would integrate with actual user model
        # For now, return empty set
        return set()
    
    async def _get_room_members(self, room_id: str) -> set[str]:
        """Get members of a room/channel."""
        # Placeholder - would integrate with room system
        return set()
    
    def get_stats(self) -> dict[str, Any]:
        """Get connection statistics."""
        total_connections = sum(len(conns) for conns in self._connections.values())
        
        return {
            "total_users": len(self._connections),
            "total_connections": total_connections,
            "online_users": len(self.get_online_users()),
            "presence_stats": {
                status: sum(1 for s in self._presence.values() if s == status)
                for status in ["online", "away", "busy", "offline"]
            },
        }