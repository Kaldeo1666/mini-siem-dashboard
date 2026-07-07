"""
ws_manager.py — WebSocket connection manager.

Keeps track of all connected browser clients.
When an alert fires, broadcasts it to all of them instantly.
"""

import asyncio
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        # List of all currently connected WebSocket clients
        self.active_connections: list[WebSocket] = []
        # Captured from main.py at startup — lets sync code (APScheduler
        # jobs running in a background thread) safely schedule an async
        # broadcast onto the main event loop.
        self.loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop

    def broadcast_sync(self, message: dict):
        """Thread-safe entry point for broadcasting from sync code (e.g. engine.py)."""
        if self.loop is None:
            print("[WS] broadcast_sync called before loop was set — dropping message")
            return
        asyncio.run_coroutine_threadsafe(self.broadcast(message), self.loop)

    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection and add to active list."""
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"[WS] Client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Remove a client when they disconnect."""
        self.active_connections.remove(websocket)
        print(f"[WS] Client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Send a message to ALL connected clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                # Client disconnected unexpectedly
                disconnected.append(connection)

        # Clean up dead connections
        for conn in disconnected:
            self.active_connections.remove(conn)


# Single global instance — imported everywhere
manager = ConnectionManager()