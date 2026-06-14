"""
ws_manager.py — WebSocket connection manager.

Keeps track of all connected browser clients.
When an alert fires, broadcasts it to all of them instantly.
"""

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        # List of all currently connected WebSocket clients
        self.active_connections: list[WebSocket] = []

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