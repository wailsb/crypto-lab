from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Crypto Lab E2E Chat")
app.mount("/static", StaticFiles(directory="/home/pengux8/crypto-lab/webapp/static"), name="static")


@dataclass
class DeviceConnection:
    device_id: str
    name: str
    ws: WebSocket
    status: str = "available"
    last_seen: float = field(default_factory=lambda: time.time())


@dataclass
class Session:
    session_id: str
    a: str
    b: str
    protocol: str
    created_at: float = field(default_factory=lambda: time.time())


DEVICES: Dict[str, DeviceConnection] = {}
SESSIONS: Dict[str, Session] = {}


@app.get("/")
async def index() -> HTMLResponse:
    with open("/home/pengux8/crypto-lab/webapp/static/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/api/protocols")
async def protocols() -> dict:
    return {
        "transport": [
            {
                "id": "ecdh-aes-gcm-ecdsa",
                "label": "ECDH + AES-GCM + ECDSA (secure)",
            }
        ],
        "payload": [
            {"id": "none", "label": "None"},
            {"id": "caesar", "label": "Caesar"},
            {"id": "vigenere", "label": "Vigenere"},
            {"id": "hill", "label": "Hill (2x2)"},
            {"id": "otp", "label": "OTP"},
        ],
    }


@app.get("/api/devices")
async def devices() -> dict:
    return {
        "devices": [
            {
                "deviceId": d.device_id,
                "name": d.name,
                "status": d.status,
                "lastSeen": d.last_seen,
            }
            for d in DEVICES.values()
        ]
    }


async def broadcast_devices() -> None:
    payload = {
        "type": "device_list",
        "devices": [
            {
                "deviceId": d.device_id,
                "name": d.name,
                "status": d.status,
                "lastSeen": d.last_seen,
            }
            for d in DEVICES.values()
        ],
    }
    await broadcast(payload)


async def broadcast(payload: dict) -> None:
    disconnected = []
    for device_id, device in list(DEVICES.items()):
        try:
            await device.ws.send_text(json.dumps(payload))
        except Exception:
            disconnected.append(device_id)
    for device_id in disconnected:
        DEVICES.pop(device_id, None)


async def send_to(device_id: str, payload: dict) -> None:
    device = DEVICES.get(device_id)
    if device:
        await device.ws.send_text(json.dumps(payload))


async def cleanup_device(device_id: str) -> None:
    sessions_to_end = [
        s for s in list(SESSIONS.values()) if s.a == device_id or s.b == device_id
    ]
    for session in sessions_to_end:
        SESSIONS.pop(session.session_id, None)
        for peer_id in [session.a, session.b]:
            if peer_id in DEVICES:
                DEVICES[peer_id].status = "available"
                await send_to(
                    peer_id,
                    {
                        "type": "session_ended",
                        "sessionId": session.session_id,
                    },
                )


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    device_id: Optional[str] = None
    try:
        while True:
            message = await ws.receive_text()
            data = json.loads(message)
            msg_type = data.get("type")

            if msg_type == "register":
                device_id = data.get("deviceId") or str(uuid.uuid4())
                name = data.get("name") or "Device"
                DEVICES[device_id] = DeviceConnection(
                    device_id=device_id,
                    name=name,
                    ws=ws,
                )
                await send_to(
                    device_id,
                    {
                        "type": "registered",
                        "deviceId": device_id,
                        "name": name,
                    },
                )
                await broadcast_devices()
            elif msg_type == "list_devices":
                await broadcast_devices()

            elif msg_type == "start_session":
                if not device_id:
                    continue
                target = data.get("to")
                protocol = data.get("protocol")
                offer = data.get("offer")
                if not target or target not in DEVICES:
                    await send_to(
                        device_id,
                        {
                            "type": "error",
                            "message": "Target device not available",
                        },
                    )
                    continue
                if DEVICES[target].status != "available":
                    await send_to(
                        device_id,
                        {
                            "type": "error",
                            "message": "Target device is busy",
                        },
                    )
                    continue
                session_id = str(uuid.uuid4())
                SESSIONS[session_id] = Session(
                    session_id=session_id,
                    a=device_id,
                    b=target,
                    protocol=protocol,
                )
                DEVICES[device_id].status = "busy"
                DEVICES[target].status = "busy"
                await send_to(
                    target,
                    {
                        "type": "session_offer",
                        "from": device_id,
                        "sessionId": session_id,
                        "protocol": protocol,
                        "offer": offer,
                    },
                )
                await broadcast_devices()

            elif msg_type == "session_answer":
                session_id = data.get("sessionId")
                target = data.get("to")
                answer = data.get("answer")
                if not session_id or session_id not in SESSIONS:
                    continue
                await send_to(
                    target,
                    {
                        "type": "session_answer",
                        "from": device_id,
                        "sessionId": session_id,
                        "answer": answer,
                    },
                )

            elif msg_type == "relay":
                target = data.get("to")
                payload = data.get("payload")
                if not target or target not in DEVICES:
                    continue
                await send_to(
                    target,
                    {
                        "type": "relay",
                        "from": device_id,
                        "payload": payload,
                    },
                )

            elif msg_type == "end_session":
                session_id = data.get("sessionId")
                session = SESSIONS.pop(session_id, None)
                if session:
                    for peer_id in [session.a, session.b]:
                        if peer_id in DEVICES:
                            DEVICES[peer_id].status = "available"
                            await send_to(
                                peer_id,
                                {
                                    "type": "session_ended",
                                    "sessionId": session_id,
                                },
                            )
                    await broadcast_devices()

            elif msg_type == "ping":
                if device_id and device_id in DEVICES:
                    DEVICES[device_id].last_seen = time.time()

    except WebSocketDisconnect:
        if device_id and device_id in DEVICES:
            DEVICES.pop(device_id, None)
            await cleanup_device(device_id)
            await broadcast_devices()
