import csv
import io
import json
import os
import shutil
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import (FastAPI, WebSocket, WebSocketDisconnect,
                     Body, UploadFile, File, Form, HTTPException, Query,
                     Depends, Request)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from core_backend.rules.behavioral_rules import ALL_RULES
from core_backend.camera_service.manager import (
    register_broadcast,
    add_camera, remove_camera, get_cameras, get_camera,
    start_camera, get_analytics_snapshot, get_camera_fps,
    pause_camera, resume_camera, stop_camera,
    set_camera_zones, get_camera_zones,
    CameraSource,
)
from core_backend.database.alerts_db import (
    init_db, save_alert, get_alerts, get_alert_stats, purge_old_alerts
)
from core_backend.auth.auth import (
    login, revoke_token, AUTH_ENABLED,
    require_auth, require_operator, require_admin,
)
from core_backend.notifications import notifier as _notifier
from core_backend.notifications import telegram_notifier as _tg

UPLOAD_DIR = Path(__file__).parent.parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)


# ─── WebSocket manager ─────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: str):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for d in dead:
            self.disconnect(d)


manager = ConnectionManager()


async def _broadcast_and_persist(message: str):
    """Broadcast to WebSocket clients, persist ALERT events, and fire notifications."""
    try:
        evt = json.loads(message)
        if evt.get("type") == "ALERT":
            save_alert(evt)
            _notifier.dispatch(evt)   # email/webhook for CRITICAL/HIGH (non-blocking)
    except Exception:
        pass
    await manager.broadcast(message)


# ─── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    purge_old_alerts(days=30)
    register_broadcast(_broadcast_and_persist)
    _tg.send_startup_notification()   # ping Telegram to confirm bot is alive
    yield


app = FastAPI(title="Raksha Vision Core", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth middleware — protects all /api/* except /api/auth/* and /api/status ──
_OPEN_PREFIXES = ("/api/auth/", "/api/status", "/api/debug/")

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if AUTH_ENABLED:
        path = request.url.path
        if path.startswith("/api/") and not any(path.startswith(p) for p in _OPEN_PREFIXES):
            token = None
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
            if not token:
                token = request.query_params.get("token")
            if not token or not __import__(
                "core_backend.auth.auth", fromlist=["verify_token"]
            ).verify_token(token):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Unauthorized — please log in"},
                )
    return await call_next(request)


# ─── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, token: Optional[str] = None):
    from core_backend.auth.auth import verify_token as _vt
    if AUTH_ENABLED and (not token or not _vt(token)):
        # Must accept before closing — closing before accept sends HTTP 403
        await ws.accept()
        await ws.close(code=4001, reason="Invalid or expired token — please log in again")
        return
    await manager.connect(ws)
    await ws.send_text(json.dumps({
        "type":    "CAMERA_LIST",
        "cameras": get_cameras(),
    }))
    try:
        while True:
            await ws.receive_text()
    except (WebSocketDisconnect, Exception):
        manager.disconnect(ws)


# ─── Camera management ─────────────────────────────────────────────────────────
@app.get("/api/cameras")
def list_cameras():
    return get_cameras()


@app.post("/api/cameras/rtsp")
async def add_rtsp_camera(
    name: str = Body(...),
    zone: str = Body(...),
    url:  str = Body(...),
):
    """Connect a live RTSP / HTTP stream."""
    cam_id = f"CAM-{uuid.uuid4().hex[:6].upper()}"
    add_camera(cam_id=cam_id, name=name, zone=zone,
               source=CameraSource.RTSP, url=url)
    await start_camera(cam_id)
    await manager.broadcast(json.dumps({
        "type":   "CAMERA_ADDED",
        "camera": {"cam_id": cam_id, "name": name, "zone": zone,
                   "source": "RTSP", "status": "CONNECTING"},
    }))
    return {"cam_id": cam_id, "status": "connecting"}


@app.post("/api/cameras/upload")
async def add_video_camera(
    name: str        = Form(...),
    zone: str        = Form(...),
    file: UploadFile = File(...),
):
    """Upload a recorded video file for continuous analysis."""
    ext     = Path(file.filename).suffix.lower()
    allowed = {".mp4", ".avi", ".mov", ".mkv", ".webm", ".flv"}
    if ext not in allowed:
        raise HTTPException(400, f"Unsupported format {ext}. Allowed: {allowed}")

    cam_id = f"CAM-{uuid.uuid4().hex[:6].upper()}"
    dest   = UPLOAD_DIR / f"{cam_id}{ext}"
    with dest.open("wb") as f:
        shutil.copyfileobj(file.file, f)

    cfg = add_camera(cam_id=cam_id, name=name, zone=zone,
                     source=CameraSource.FILE, url=str(dest))
    cfg.loop_video = True   # loop uploaded videos so the analyser has continuous footage
    await start_camera(cam_id)
    await manager.broadcast(json.dumps({
        "type":   "CAMERA_ADDED",
        "camera": {"cam_id": cam_id, "name": name, "zone": zone,
                   "source": "FILE", "status": "CONNECTING"},
    }))
    return {"cam_id": cam_id, "filename": dest.name, "status": "processing"}


@app.post("/api/cameras/webcam")
async def add_webcam(
    name:      str = Body(...),
    zone:      str = Body(...),
    device_id: int = Body(0),
):
    """Connect a local USB/built-in webcam."""
    cam_id = f"CAM-{uuid.uuid4().hex[:6].upper()}"
    add_camera(cam_id=cam_id, name=name, zone=zone,
               source=CameraSource.WEBCAM, url=str(device_id))
    await start_camera(cam_id)
    await manager.broadcast(json.dumps({
        "type":   "CAMERA_ADDED",
        "camera": {"cam_id": cam_id, "name": name, "zone": zone,
                   "source": "WEBCAM", "status": "CONNECTING"},
    }))
    return {"cam_id": cam_id, "status": "connecting"}


@app.delete("/api/cameras/{cam_id}")
async def delete_camera(cam_id: str):
    cfg = get_camera(cam_id)
    if not cfg:
        raise HTTPException(404, "Camera not found")
    remove_camera(cam_id)
    await manager.broadcast(json.dumps({
        "type": "CAMERA_REMOVED", "camera_id": cam_id
    }))
    return {"status": "removed"}


@app.post("/api/cameras/{cam_id}/pause")
async def pause_camera_endpoint(cam_id: str):
    cfg = get_camera(cam_id)
    if not cfg:
        raise HTTPException(404, "Camera not found")
    pause_camera(cam_id)
    await manager.broadcast(json.dumps({
        "type": "CAM_STATUS", "camera_id": cam_id, "status": "PAUSED"
    }))
    return {"status": "paused"}


@app.post("/api/cameras/{cam_id}/resume")
async def resume_camera_endpoint(cam_id: str):
    cfg = get_camera(cam_id)
    if not cfg:
        raise HTTPException(404, "Camera not found")
    resume_camera(cam_id)
    await manager.broadcast(json.dumps({
        "type": "CAM_STATUS", "camera_id": cam_id, "status": "LIVE"
    }))
    return {"status": "resumed"}


@app.post("/api/cameras/{cam_id}/stop")
async def stop_camera_endpoint(cam_id: str):
    cfg = get_camera(cam_id)
    if not cfg:
        raise HTTPException(404, "Camera not found")
    stop_camera(cam_id)
    await manager.broadcast(json.dumps({
        "type": "CAM_STATUS", "camera_id": cam_id, "status": "OFFLINE"
    }))
    return {"status": "stopped"}


# ─── Analytics ─────────────────────────────────────────────────────────────────
@app.get("/api/analytics")
def analytics():
    return get_analytics_snapshot()


# ─── Rules ─────────────────────────────────────────────────────────────────────
@app.get("/api/rules")
def list_rules():
    return [
        {
            "rule_id":    r.rule_id,
            "name":       r.name,
            "category":   r.category.value,
            "severity":   r.severity.value,
            "description": r.description,
            "trigger":    r.trigger,
            "action":     r.action,
            "tags":       r.tags,
            "enabled":    r.enabled,
        }
        for r in ALL_RULES
    ]


# ─── Manual alert push (from external CV pipeline) ────────────────────────────
@app.post("/api/alert")
async def push_alert(alert: dict = Body(...)):
    """Push an alert from an external behavioural analysis pipeline."""
    alert["type"] = "ALERT"
    await _broadcast_and_persist(json.dumps(alert))
    return {"status": "broadcast", "clients": len(manager.active)}


# ─── Debug / diagnostics ───────────────────────────────────────────────────────
@app.get("/api/debug/state")
def debug_state():
    """
    Live pipeline state for each camera.
    Open http://127.0.0.1:8000/api/debug/state in a browser to see what the
    detection engine is actually doing — frame count, tracks, warmup status, etc.
    """
    from core_backend.camera_service.manager import _analysers, _cameras
    out = {}
    for cam_id, analyser in _analysers.items():
        cfg = _cameras.get(cam_id)
        active = [t for t in analyser.tracks.values()
                  if time.time() - t.last_seen < 2.0]
        mature = [t for t in active
                  if len(t.positions) >= analyser.MIN_TRACK_POS
                  and t.dwell_sec() >= analyser.MIN_TRACK_SEC]
        out[cam_id] = {
            "camera_name":      cfg.name if cfg else "?",
            "source":           cfg.source.value if cfg else "?",
            "status":           cfg.status.value if cfg else "?",
            "frame_n":          analyser.frame_n,
            "warmup_frames":    analyser.WARMUP_FRAMES,
            "warmup_done":      analyser.frame_n >= analyser.WARMUP_FRAMES,
            "yolo_available":   analyser._use_yolo,
            "active_tracks":    len(active),
            "mature_tracks":    len(mature),
            "conf_threshold":   analyser.CONF_THRESHOLD,
            "tracks": [
                {
                    "uid":       t.uid,
                    "state":     t.state.value,
                    "velocity":  round(t.smooth_velocity(0.6), 1),
                    "dwell_s":   round(t.dwell_sec(), 1),
                    "positions": len(t.positions),
                    "mature":    t in mature,
                }
                for t in active
            ],
            "rate_log":         {k: len(v) for k, v in analyser.rate_log.items()},
            "fired_rules":      list(analyser.fired.keys())[-10:],   # last 10
        }
    if not out:
        return {"message": "No active cameras. Upload a video first."}
    return out


# ─── Alert history (SQLite) ────────────────────────────────────────────────────
@app.get("/api/alerts")
def list_alerts(
    limit:     int            = Query(100, ge=1, le=1000),
    offset:    int            = Query(0,   ge=0),
    camera_id: Optional[str] = Query(None),
    severity:  Optional[str] = Query(None),
    since:     Optional[float] = Query(None, description="Unix timestamp — return alerts after this time"),
):
    return get_alerts(limit=limit, offset=offset,
                      camera_id=camera_id, severity=severity, since_ts=since)


@app.get("/api/alerts/stats")
def alert_stats():
    return get_alert_stats()


@app.delete("/api/alerts")
def clear_old_alerts(days: int = Query(30, ge=1)):
    purge_old_alerts(days=days)
    return {"status": "purged", "older_than_days": days}


# ─── Zone editor ───────────────────────────────────────────────────────────────
@app.get("/api/cameras/{cam_id}/zones")
def get_zones(cam_id: str):
    cfg = get_camera(cam_id)
    if not cfg:
        raise HTTPException(404, "Camera not found")
    return get_camera_zones(cam_id)


@app.put("/api/cameras/{cam_id}/zones")
async def update_zones(cam_id: str, body: dict = Body(...)):
    cfg = get_camera(cam_id)
    if not cfg:
        raise HTTPException(404, "Camera not found")
    checkout   = body.get("checkout",   [0.60, 0.60, 1.0, 1.0])
    restricted = body.get("restricted", [0.75, 0.00, 1.0, 0.35])
    if len(checkout) != 4 or len(restricted) != 4:
        raise HTTPException(400, "Each zone must be [x1, y1, x2, y2] fractions 0–1")
    set_camera_zones(cam_id, checkout, restricted)
    await manager.broadcast(json.dumps({
        "type": "ZONES_UPDATED", "camera_id": cam_id,
        "checkout": checkout, "restricted": restricted,
    }))
    return {"status": "updated", "checkout": checkout, "restricted": restricted}


# ─── Auth ──────────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def auth_login(request: Request):
    body = await request.json()
    u = body.get("username", "")
    p = body.get("password", "")
    print(f"[LOGIN] user={repr(u)} pass={repr(p)}")
    from core_backend.auth.auth import get_credentials
    eu, ep = get_credentials()
    print(f"[LOGIN] expected user={repr(eu)} pass={repr(ep)}")
    token = login(u, p)
    if not token:
        raise HTTPException(401, "Invalid credentials")
    return {"token": token, "auth_enabled": AUTH_ENABLED}


@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    token = body.get("token", "")
    if token:
        revoke_token(token)
    return {"status": "logged out"}


@app.get("/api/auth/status")
def auth_status():
    return {"auth_enabled": AUTH_ENABLED}


# ─── RBAC: current user info ───────────────────────────────────────────────────
@app.get("/api/auth/me")
async def auth_me(role: str = Depends(require_auth)):
    """Return the authenticated caller's role."""
    return {"role": role, "auth_enabled": AUTH_ENABLED}


# ─── System status ─────────────────────────────────────────────────────────────
@app.get("/api/status")
def status():
    return {
        "status":       "running",
        "version":      "2.0.0",
        "cameras":      len(get_cameras()),
        "rules_loaded": len(ALL_RULES),
        "ws_clients":   len(manager.active),
        "auth_enabled": AUTH_ENABLED,
        "db_stats":     get_alert_stats(),
    }


# ─── System health ─────────────────────────────────────────────────────────────
@app.get("/api/system/health")
def system_health():
    """CPU, memory, per-camera FPS, active stream count, alert rate."""
    try:
        import psutil
        cpu_pct = psutil.cpu_percent(interval=0.2)
        mem     = psutil.virtual_memory()
        mem_info = {
            "total_mb":  round(mem.total  / 1024 ** 2),
            "used_mb":   round(mem.used   / 1024 ** 2),
            "percent":   round(mem.percent, 1),
        }
    except ImportError:
        cpu_pct  = -1
        mem_info = {}

    cameras     = get_cameras()
    active_cams = [c for c in cameras if c.get("status") in ("LIVE", "RECORDING")]
    fps_data    = get_camera_fps()
    recent_alerts = get_alerts(limit=1000, since_ts=time.time() - 60)

    return {
        "status":            "ok",
        "cpu_percent":       cpu_pct,
        "memory":            mem_info,
        "cameras": {
            "total":          len(cameras),
            "active_streams": len(active_cams),
        },
        "fps_per_camera":    fps_data,
        "alert_rate_per_min": len(recent_alerts),
        "ws_clients":        len(manager.active),
        "timestamp":         time.time(),
    }


# ─── Alert export ──────────────────────────────────────────────────────────────
_EXPORT_FIELDS = [
    "id", "event_id", "rule_id", "rule_name", "category", "severity",
    "risk_score", "person_id", "camera_id", "camera_name", "zone",
    "description", "trigger", "action", "timestamp", "stored_at",
]


def _export_csv(rows: list) -> StreamingResponse:
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf, fieldnames=_EXPORT_FIELDS,
        extrasaction="ignore", lineterminator="\n",
    )
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    buf.seek(0)
    filename = f"raksha_alerts_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _export_pdf(rows: list) -> StreamingResponse:
    try:
        from fpdf import FPDF  # fpdf2
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="PDF export requires fpdf2. Run: pip install fpdf2",
        )

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Raksha Vision Core — Alert Export", ln=True, align="C")
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(
        0, 5,
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}   Records: {len(rows)}",
        ln=True, align="C",
    )
    pdf.ln(4)

    # Column definitions: (header, width)
    cols = [
        ("Severity", 22), ("Rule ID", 28), ("Rule Name", 52),
        ("Camera",   36), ("Timestamp", 44),
    ]

    # Header row
    pdf.set_fill_color(30, 30, 30)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 7)
    for label, w in cols:
        pdf.cell(w, 7, label, border=1, fill=True)
    pdf.ln()

    # Data rows
    pdf.set_font("Helvetica", "", 7)
    fill = False
    for r in rows:
        if pdf.get_y() > 270:
            pdf.add_page()
            # Re-draw header on new page
            pdf.set_fill_color(30, 30, 30)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 7)
            for label, w in cols:
                pdf.cell(w, 7, label, border=1, fill=True)
            pdf.ln()
            pdf.set_font("Helvetica", "", 7)

        sev = r.get("severity", "")
        if sev == "CRITICAL":
            pdf.set_text_color(180, 0,  0)
        elif sev == "HIGH":
            pdf.set_text_color(200, 80, 0)
        else:
            pdf.set_text_color(0,   0,  0)

        bg = (245, 245, 245) if fill else (255, 255, 255)
        pdf.set_fill_color(*bg)

        pdf.cell(22, 6, sev,                                          border=1, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(28, 6, str(r.get("rule_id",   ""))[:16],             border=1, fill=True)
        pdf.cell(52, 6, str(r.get("rule_name", ""))[:32],             border=1, fill=True)
        cam = r.get("camera_name") or r.get("camera_id", "")
        pdf.cell(36, 6, str(cam)[:20],                                border=1, fill=True)
        pdf.cell(44, 6, str(r.get("timestamp", ""))[:19],             border=1, fill=True)
        pdf.ln()
        fill = not fill

    raw = pdf.output()
    filename = f"raksha_alerts_{time.strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        io.BytesIO(raw),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/api/alerts/export")
async def export_alerts(
    format:    str            = Query("csv", pattern="^(csv|pdf)$"),
    camera_id: Optional[str]  = Query(None),
    severity:  Optional[str]  = Query(None),
    since:     Optional[float] = Query(None, description="Start Unix timestamp"),
    until:     Optional[float] = Query(None, description="End Unix timestamp"),
    _role: str = Depends(require_auth),
):
    """Download alert history as CSV or PDF with optional filters."""
    rows = get_alerts(
        limit=10_000, camera_id=camera_id, severity=severity, since_ts=since
    )
    if until is not None:
        rows = [r for r in rows if r.get("stored_at", 0) <= until]

    if format == "pdf":
        return _export_pdf(rows)
    return _export_csv(rows)


# ─── Frontend ──────────────────────────────────────────────────────────────────
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")

if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    def serve_frontend():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
else:
    @app.get("/")
    def home():
        return {"status": "Raksha Vision Core running. frontend/dist not found."}


# ─── Favicon (suppress browser 404 noise) ─────────────────────────────────────
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    ico = Path(FRONTEND_DIR) / "favicon.ico"
    if ico.exists():
        return FileResponse(str(ico), media_type="image/x-icon")
    return Response(status_code=204)  # No Content — silent, no 404 logged
