"""
routers/ws.py — WebSocket endpoint for real-time alert push.

The frontend (AlertsPanel.jsx) connects here on mount. Whenever engine.py
fires a new alert, ws_manager.broadcast_sync(...) pushes it to every
connected client instantly, without polling.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from ws_manager import manager

router = APIRouter()


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect the client to send anything meaningful, but
            # we need to await something to keep the connection open and
            # detect disconnects promptly.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)