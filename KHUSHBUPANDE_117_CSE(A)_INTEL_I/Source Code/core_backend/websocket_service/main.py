from fastapi import APIRouter, WebSocket, Body
import json

router = APIRouter()
clients = []

@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    clients.append(ws)
    try:
        while True:
            await ws.receive_text()
    except Exception:
        clients.remove(ws)

@router.post("/send_alert")
async def send_alert(alert: dict = Body(...)):
    disconnected = []
    for c in clients:
        try:
            await c.send_text(json.dumps(alert))
        except Exception:
            disconnected.append(c)
    for c in disconnected:
        clients.remove(c)
    return {"status": "sent"}
