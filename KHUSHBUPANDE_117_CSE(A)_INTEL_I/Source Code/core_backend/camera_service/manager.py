"""
Raksha Vision Core — Production Camera Manager v5
================================================
Architecture:
  - Reader task  : reads raw frames into asyncio.Queue (no processing)
  - Worker task  : pops frames, runs CV, fires events
  - Human-state  : IDLE / STANDING / WALKING / RUNNING / FLEEING / FALLEN / SITTING
  - Temporal gate: every rule requires N seconds of *continuous* condition before firing
  - Per-track dedup : each rule can fire for a track at most once per cooldown window
  - Camera rate-limit: hard cap on alerts per severity per 60 s
  - RTSP reconnect  : exponential back-off up to 30 s
  - FILE pause/resume/stop via flags on CameraConfig
"""

import asyncio
import base64
import concurrent.futures
import json
import math
import os
import queue as _queue_mod
import time
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Callable, Awaitable, Dict, List, Optional, Set, Tuple

import cv2
import numpy as np

from core_backend.camera_service.reid_engine import REID
from core_backend.camera_service.rule_engine import RuleEngine

# Set RAKSHA_DEBUG=1 to enable per-frame pipeline logging to the console.
# Usage (Windows):  set RAKSHA_DEBUG=1  && uvicorn ...
_PIPE_DEBUG = os.environ.get("RAKSHA_DEBUG") == "1"

# ── Snapshot directory — alert frames saved here for Telegram notifications ──
_SNAPSHOT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "snapshots")
os.makedirs(_SNAPSHOT_DIR, exist_ok=True)
_SNAPSHOT_SEVERITIES = {"CRITICAL", "HIGH"}  # only save snapshots for these


def _prune_snapshots(directory: str, max_age_sec: int = 3600):
    """Delete snapshot files older than max_age_sec to keep disk use low."""
    try:
        cutoff = time.time() - max_age_sec
        for fname in os.listdir(directory):
            fpath = os.path.join(directory, fname)
            if os.path.isfile(fpath) and os.path.getmtime(fpath) < cutoff:
                os.remove(fpath)
    except Exception:
        pass

def _pdebug(msg: str):
    if _PIPE_DEBUG:
        print(f"[RAKSHA] {time.strftime('%H:%M:%S')} {msg}", flush=True)


# ─── RTSP Reader — dedicated daemon thread per stream ────────────────────────
class _RTSPReader:
    """
    Runs cap.read() in its own thread so the asyncio event loop never blocks.

    The internal queue holds at most QUEUE_SIZE frames; when full the oldest
    is dropped so the consumer always receives the *latest* real-time frame.
    Reconnects automatically with exponential back-off on stream loss.
    """
    QUEUE_SIZE = 2

    def __init__(self, url: str):
        self.url       = url
        self._q        = _queue_mod.Queue(maxsize=self.QUEUE_SIZE)
        self._stop_evt = threading.Event()
        self._thread   = threading.Thread(target=self._run, daemon=True,
                                          name=f"rtsp-{url[-24:]}")
        self.connected = False
        self.backoff   = 1.0

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop_evt.set()

    def get_nowait(self) -> Optional[np.ndarray]:
        try:
            return self._q.get_nowait()
        except _queue_mod.Empty:
            return None

    def _push(self, frame: np.ndarray):
        if self._q.full():
            try:
                self._q.get_nowait()      # drop oldest
            except _queue_mod.Empty:
                pass
        try:
            self._q.put_nowait(frame)
        except _queue_mod.Full:
            pass

    def _run(self):
        while not self._stop_evt.is_set():
            cap = cv2.VideoCapture(self.url)
            cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            if not cap.isOpened():
                self.connected = False
                self._stop_evt.wait(self.backoff)
                self.backoff = min(self.backoff * 2, 30.0)
                continue
            self.connected = True
            self.backoff   = 1.0
            while not self._stop_evt.is_set():
                ret, frame = cap.read()
                if not ret:
                    break
                self._push(frame)
            cap.release()
            self.connected = False
            if not self._stop_evt.is_set():
                self._stop_evt.wait(self.backoff)
                self.backoff = min(self.backoff * 2, 30.0)


# ─── Optional YOLO detector (auto-downloads yolov8n.pt on first run) ──────────
class _YOLODet:
    _model    = None
    _loaded   = False
    available = False
    _device   = "cpu"      # set to "cuda" automatically when a GPU is available
    _last_confs: List[float] = []   # per-bbox detection confidence from last call

    @classmethod
    def ensure(cls):
        if cls._loaded:
            return cls.available
        cls._loaded = True
        # Auto-detect CUDA — falls back to CPU silently if torch not installed
        try:
            import torch
            cls._device = "cuda" if torch.cuda.is_available() else "cpu"
            if cls._device == "cuda":
                gpu_name = torch.cuda.get_device_name(0)
                import logging as _lg
                _lg.getLogger("raksha.yolo").info(f"[YOLO] GPU detected: {gpu_name}")
        except ImportError:
            cls._device = "cpu"
        try:
            import logging
            logging.getLogger("ultralytics").setLevel(logging.WARNING)
            from ultralytics import YOLO

            # ── TensorRT acceleration (optional) ──────────────────────────────
            # To enable: export model first →
            #   yolo export model=yolov8n.pt format=engine device=0
            # Then set env var: RAKSHA_TRT_ENGINE=yolov8n.engine
            # The .engine file is device-specific — regenerate after driver updates.
            import os as _os
            _trt_path = _os.environ.get("RAKSHA_TRT_ENGINE", "")
            if _trt_path and _os.path.isfile(_trt_path) and cls._device == "cuda":
                import logging as _lg
                _lg.getLogger("raksha.yolo").info(
                    f"[YOLO] Loading TensorRT engine: {_trt_path}"
                )
                cls._model = YOLO(_trt_path)   # ultralytics handles .engine natively
            else:
                cls._model = YOLO("yolov8n.pt")
            cls.available = True
        except Exception:
            cls.available = False
        return cls.available

    @classmethod
    def detect(cls, frame: np.ndarray) -> Optional[List[Tuple]]:
        """Return list of (x,y,w,h) person bboxes, or None if unavailable."""
        if not cls.ensure():
            return None
        try:
            results = cls._model(frame, classes=[0], verbose=False,
                                 imgsz=640, device=cls._device,
                                 half=(cls._device == "cuda"))
            boxes = []
            cls._last_confs = []
            for r in results:
                for b in r.boxes:
                    x1,y1,x2,y2 = (int(v) for v in b.xyxy[0].tolist())
                    c = float(b.conf[0])
                    if c >= 0.40:
                        boxes.append((x1, y1, x2-x1, y2-y1))
                        cls._last_confs.append(c)
            return boxes
        except Exception:
            cls._last_confs = []
            return None

    @classmethod
    def detect_pose(cls, frame: np.ndarray):
        """Return (boxes, kps_list) where kps_list[i] is (17,3) array or None."""
        if not cls.ensure():
            return None, None
        try:
            from ultralytics import YOLO as _YOLO
            if not hasattr(cls, "_pose_model"):
                cls._pose_model = _YOLO("yolov8n-pose.pt")
            results = cls._pose_model(frame, classes=[0], verbose=False,
                                      imgsz=640, device=cls._device,
                                      half=(cls._device == "cuda"))
            boxes, kps_list = [], []
            cls._last_confs = []
            for r in results:
                for i, b in enumerate(r.boxes):
                    c = float(b.conf[0])
                    if c < 0.40:
                        continue
                    x1,y1,x2,y2 = (int(v) for v in b.xyxy[0].tolist())
                    boxes.append((x1, y1, x2-x1, y2-y1))
                    cls._last_confs.append(c)
                    if r.keypoints is not None and i < len(r.keypoints.data):
                        kps_list.append(r.keypoints.data[i].cpu().numpy())
                    else:
                        kps_list.append(None)
            return boxes, kps_list
        except Exception:
            cls._last_confs = []
            return None, None


# ─── Enums ─────────────────────────────────────────────────────────────────────
class CameraStatus(str, Enum):
    CONNECTING = "CONNECTING"
    LIVE       = "LIVE"
    RECORDING  = "RECORDING"
    PAUSED     = "PAUSED"
    ERROR      = "ERROR"
    OFFLINE    = "OFFLINE"

class CameraSource(str, Enum):
    RTSP   = "RTSP"
    FILE   = "FILE"
    WEBCAM = "WEBCAM"

class HumanState(str, Enum):
    IDLE      = "IDLE"
    STANDING  = "STANDING"
    SITTING   = "SITTING"
    WALKING   = "WALKING"
    RUNNING   = "RUNNING"
    FLEEING   = "FLEEING"
    FALLEN    = "FALLEN"


# ─── Data models ───────────────────────────────────────────────────────────────
@dataclass
class CameraConfig:
    cam_id:    str
    name:      str
    zone:      str
    source:    CameraSource
    url:       str
    enabled:   bool         = True
    fps_cap:   int          = 15
    status:    CameraStatus = CameraStatus.CONNECTING
    error_msg: str          = ""
    added_at:  float        = field(default_factory=time.time)
    paused:    bool         = False
    stopped:   bool         = False
    loop_video:bool         = False  # FILE: stop when finished (prevents alert storms on looped footage)


@dataclass
class RuleTrigger:
    """Sliding-window temporal accumulator for one rule on one subject."""
    start_ts:   float
    last_ts:    float
    hit_count:  int


@dataclass
class InteractionState:
    """
    Per-pair interaction snapshot — recomputed every frame by _compute_interaction().

    Fields
    ------
    active        : proximity sustained ≥ 0.5 s
    start_ts      : when continuous proximity first detected
    duration      : seconds of uninterrupted proximity
    distance      : current pixel distance between centroids
    closing_speed : px/s; positive = approaching, negative = separating
    approaching   : True when closing_speed > 5 px/s
    rel_velocity  : magnitude of per-person speed difference
    score         : 0–1 composite (distance + duration + approach + rel_vel)
    """
    active:        bool  = False
    start_ts:      float = 0.0
    duration:      float = 0.0
    distance:      float = 9999.0
    closing_speed: float = 0.0
    approaching:   bool  = False
    rel_velocity:  float = 0.0
    score:         float = 0.0


@dataclass
class PersonTrack:
    uid:         str
    first_seen:  float
    last_seen:   float
    positions:   deque          # (cx, cy, ts)
    bboxes:      deque          # (x, y, w, h)
    zone_since:  float          = 0.0
    checkout_visited: bool      = False
    alerted:     set            = field(default_factory=set)
    # state
    state:       HumanState     = HumanState.IDLE
    state_ts:    float          = 0.0   # when current state started
    # temporal accumulators: rule_id → RuleTrigger
    triggers:    dict           = field(default_factory=dict)
    # re-ID: small frame crops sampled during life of track
    frame_crops: list           = field(default_factory=list)
    # state-based alert de-dup: rules in this set are ACTIVE (already fired while
    # condition is continuously true — cleared when condition goes False via tgate_reset)
    alert_active: set           = field(default_factory=set)

    # ── velocity (0.4-second time-window, immune to tiny frame-dt) ───────────
    def velocity_px_s(self) -> float:
        if len(self.positions) < 2:
            return 0.0
        now = time.time()
        win = [(x,y,t) for x,y,t in self.positions if now - t <= 0.4]
        if len(win) < 2:
            x1,y1,t1 = self.positions[-2]
            x2,y2,t2 = self.positions[-1]
            dt = t2 - t1
            if dt < 0.08:
                return 0.0
            return math.hypot(x2-x1, y2-y1) / dt
        x1,y1,t1 = win[0]; x2,y2,t2 = win[-1]
        dt = max(t2-t1, 0.08)
        return math.hypot(x2-x1, y2-y1) / dt

    def smooth_velocity(self, window: float = 1.0) -> float:
        """Average velocity over last `window` seconds — less noisy."""
        now = time.time()
        pts = [(x,y,t) for x,y,t in self.positions if now - t <= window]
        if len(pts) < 3:
            return self.velocity_px_s()
        vels = []
        for i in range(1, len(pts)):
            x1,y1,t1 = pts[i-1]; x2,y2,t2 = pts[i]
            dt = max(t2-t1, 0.001)
            vels.append(math.hypot(x2-x1, y2-y1) / dt)
        return float(np.mean(vels)) if vels else 0.0

    def displacement_px(self, over_sec: float = 30.0) -> float:
        now = time.time()
        pts = [(x,y) for x,y,t in self.positions if now-t <= over_sec]
        if len(pts) < 2:
            return 0.0
        xs,ys = zip(*pts)
        return math.hypot(max(xs)-min(xs), max(ys)-min(ys))

    def dwell_sec(self) -> float:
        return time.time() - self.first_seen

    def last_pos(self) -> Tuple[int,int]:
        if not self.positions:
            return (0,0)
        return (int(self.positions[-1][0]), int(self.positions[-1][1]))

    def aspect_ratio(self) -> float:
        if not self.bboxes:
            return 1.0
        _,_,w,h = self.bboxes[-1]
        return w / max(h, 1)

    def is_mobile(self) -> bool:
        return self.state in (HumanState.WALKING, HumanState.RUNNING, HumanState.FLEEING)


# ─── Global state ──────────────────────────────────────────────────────────────
_cameras:      Dict[str, CameraConfig]  = {}
_tasks:        Dict[str, asyncio.Task]  = {}
_broadcast:    Optional[Callable[[str], Awaitable[None]]] = None
_analytics:    Dict[str, dict]          = {}
_analysers:    Dict[str, "FrameAnalyser"] = {}
_camera_fps:   Dict[str, float]          = {}
# Per-camera resources — each camera gets its own thread + RTSP reader
_cam_executors: Dict[str, concurrent.futures.ThreadPoolExecutor] = {}
_rtsp_readers:  Dict[str, _RTSPReader]   = {}


def _get_cam_executor(cam_id: str) -> concurrent.futures.ThreadPoolExecutor:
    """Return (creating if needed) a 1-worker executor dedicated to cam_id.

    Isolating inference per camera prevents one slow camera from stalling
    others when they share the default thread-pool.
    """
    if cam_id not in _cam_executors:
        _cam_executors[cam_id] = concurrent.futures.ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix=f"raksha_cv_{cam_id}",
        )
    return _cam_executors[cam_id]


def register_broadcast(fn):
    global _broadcast
    _broadcast = fn

def add_camera(cam_id, name, zone, source, url) -> CameraConfig:
    cfg = CameraConfig(cam_id=cam_id, name=name, zone=zone, source=source, url=url)
    _cameras[cam_id] = cfg
    _analytics[cam_id] = dict(
        name=name, zone=zone, footfall=0, exits=0,
        checkout_exits=0, active=0, alerts=0,
        dwell_sum=0.0, dwell_cnt=0, avg_dwell=0.0,
        queue=0, zone_risk="LOW"
    )
    return cfg

def remove_camera(cam_id):
    cfg = _cameras.get(cam_id)
    if cfg:
        cfg.stopped = True
    _cameras.pop(cam_id, None)
    _analytics.pop(cam_id, None)
    _camera_fps.pop(cam_id, None)
    # Stop RTSP reader thread
    reader = _rtsp_readers.pop(cam_id, None)
    if reader:
        reader.stop()
    # Shutdown per-camera CV executor
    executor = _cam_executors.pop(cam_id, None)
    if executor:
        executor.shutdown(wait=False)
    t = _tasks.pop(cam_id, None)
    if t and not t.done():
        t.cancel()

def pause_camera(cam_id):
    cfg = _cameras.get(cam_id)
    if cfg and cfg.source == CameraSource.FILE:
        cfg.paused = True
        cfg.status = CameraStatus.PAUSED

def resume_camera(cam_id):
    cfg = _cameras.get(cam_id)
    if cfg:
        cfg.paused = False
        cfg.status = CameraStatus.RECORDING if cfg.source == CameraSource.FILE else CameraStatus.LIVE

def stop_camera(cam_id):
    cfg = _cameras.get(cam_id)
    if cfg:
        cfg.stopped = True
        cfg.paused  = False

def get_cameras():
    out = []
    for c in _cameras.values():
        d = asdict(c)
        d["source"] = c.source.value
        d["status"] = c.status.value
        out.append(d)
    return out

def get_camera(cam_id):
    return _cameras.get(cam_id)

def set_camera_zones(cam_id: str, checkout: list, restricted: list):
    """Update checkout and restricted zone fractions on the live analyser."""
    analyser = _analysers.get(cam_id)
    if analyser:
        analyser.checkout_zone   = tuple(checkout)
        analyser.restricted_zone = tuple(restricted)

def get_camera_zones(cam_id: str) -> dict:
    analyser = _analysers.get(cam_id)
    if analyser:
        return {
            "checkout":   list(analyser.checkout_zone),
            "restricted": list(analyser.restricted_zone),
        }
    return {
        "checkout":   [0.60, 0.60, 1.0, 1.0],
        "restricted": [0.75, 0.00, 1.0, 0.35],
    }

def get_camera_fps() -> Dict[str, float]:
    """Return a dict of cam_id → measured processing FPS (updated every 10s)."""
    return dict(_camera_fps)

def get_analytics_snapshot():
    foot  = sum(a["footfall"]        for a in _analytics.values())
    acts  = sum(a["active"]          for a in _analytics.values())
    alrts = sum(a["alerts"]          for a in _analytics.values())
    ckout = sum(a["checkout_exits"]  for a in _analytics.values())
    dws   = [a["avg_dwell"] for a in _analytics.values() if a["avg_dwell"] > 0]
    conv  = round(min(100, max(0, (ckout / max(foot,1)) * 100)), 1)
    return {
        "type":             "ANALYTICS_SNAPSHOT",
        "footfall_today":   foot,
        "active_persons":   acts,
        "conversion_rate":  conv,
        "avg_dwell_min":    round(sum(dws)/len(dws)/60, 1) if dws else 0.0,
        "queue_length":     max((a["queue"] for a in _analytics.values()), default=0),
        "alerts_today":     alrts,
        "cameras_online":   len(_cameras),
        "zones": [{"zone":a["zone"],"traffic":a["active"],"risk":a["zone_risk"]}
                  for a in _analytics.values()],
    }


# ─── Start/stop ────────────────────────────────────────────────────────────────
async def start_camera(cam_id):
    if cam_id in _tasks and not _tasks[cam_id].done():
        return
    _tasks[cam_id] = asyncio.create_task(_capture_loop(cam_id))

async def start_all():
    for cid in list(_cameras):
        await start_camera(cid)


# ─── Capture loop — real-time multi-camera pipeline ───────────────────────────
async def _capture_loop(cam_id: str):
    """
    Architecture per camera:
      RTSP   → _RTSPReader daemon thread → frame queue → per-camera executor (CV)
      FILE   → cap.read() in per-camera executor         → per-camera executor (CV)
      WEBCAM → cap.read() in per-camera executor         → per-camera executor (CV)

    Key properties:
      - cap.read() NEVER blocks the event loop (runs in thread for all sources)
      - Each camera has its own 1-worker ThreadPoolExecutor → no inter-camera contention
      - Adaptive frame skip when processing falls behind (analyser._skip_n > 1)
      - RTSP auto-reconnects with exp back-off in reader thread
    """
    cfg = _cameras.get(cam_id)
    if not cfg:
        return

    analyser        = FrameAnalyser(cam_id, cfg.name, cfg.zone)
    _analysers[cam_id] = analyser
    broadcast_ivl   = 1.0 / max(cfg.fps_cap, 1)
    process_ivl     = 0.10
    last_broadcast  = 0.0
    last_process    = 0.0
    loop            = asyncio.get_event_loop()
    backoff         = 1.0
    _fps_count      = 0
    _fps_window_ts  = time.time()
    cam_executor    = _get_cam_executor(cam_id)   # dedicated 1-worker thread

    while not cfg.stopped:
        await _set_status(cam_id, CameraStatus.CONNECTING)
        src = cfg.url
        if cfg.source == CameraSource.WEBCAM:
            src = int(cfg.url) if cfg.url.isdigit() else 0

        rtsp_reader: Optional[_RTSPReader] = None
        cap = None

        # ── RTSP — start dedicated reader thread ─────────────────────────────
        if cfg.source == CameraSource.RTSP:
            rtsp_reader = _RTSPReader(src)
            rtsp_reader.start()
            _rtsp_readers[cam_id] = rtsp_reader
            for _ in range(20):          # wait up to 10 s for first connect
                if rtsp_reader.connected:
                    break
                await asyncio.sleep(0.5)
            if not rtsp_reader.connected:
                rtsp_reader.stop()
                _rtsp_readers.pop(cam_id, None)
                await _set_status(cam_id, CameraStatus.ERROR, f"Cannot connect: {src}")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
                continue

        # ── FILE / WEBCAM — open synchronously (local, fast) ─────────────────
        else:
            cap = cv2.VideoCapture(src)
            if not cap.isOpened():
                await _set_status(cam_id, CameraStatus.ERROR, f"Cannot open: {cfg.url}")
                if cfg.source == CameraSource.FILE:
                    return
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
                continue

        backoff = 1.0
        st = CameraStatus.RECORDING if cfg.source == CameraSource.FILE else CameraStatus.LIVE
        await _set_status(cam_id, st)

        try:
            while not cfg.stopped:
                # ── Pause (FILE only) ─────────────────────────────────────────
                if cfg.paused:
                    await asyncio.sleep(0.1)
                    continue

                # ── Read next frame ───────────────────────────────────────────
                frame: Optional[np.ndarray] = None

                if rtsp_reader is not None:
                    # Non-blocking peek from RTSP reader queue
                    frame = rtsp_reader.get_nowait()
                    if frame is None:
                        if not rtsp_reader.connected:
                            break           # stream lost → outer reconnect loop
                        await asyncio.sleep(0.005)
                        continue
                else:
                    # FILE / WEBCAM: run in executor so event loop stays free
                    ret, frame = await loop.run_in_executor(
                        cam_executor, cap.read)
                    if not ret:
                        if cfg.source == CameraSource.FILE:
                            if cfg.loop_video:
                                await loop.run_in_executor(
                                    cam_executor,
                                    lambda: cap.set(cv2.CAP_PROP_POS_FRAMES, 0))
                                analyser.reset_tracks()
                                analyser.reset_bg()   # re-init MOG2 so it doesn't learn video content as background
                                await asyncio.sleep(0.1)
                                continue
                            else:
                                await _set_status(cam_id, CameraStatus.OFFLINE)
                                break
                        break   # WEBCAM dropped

                now = time.time()

                # ── Rate throttle ─────────────────────────────────────────────
                ivl = process_ivl if cfg.source == CameraSource.FILE else broadcast_ivl
                if now - last_process < ivl:
                    await asyncio.sleep(0.002)
                    continue
                last_process = now
                _fps_count  += 1

                # ── Adaptive skip: under load, broadcast without inference ─────
                # analyser._skip_n is raised automatically inside process()
                # when average processing time exceeds the target.
                if analyser._skip_n > 1 and (_fps_count % analyser._skip_n != 0):
                    if now - last_broadcast >= broadcast_ivl and _broadcast:
                        last_broadcast = now
                        sm = cv2.resize(frame, (640, 360), interpolation=cv2.INTER_AREA)
                        _, buf = cv2.imencode('.jpg', sm, [cv2.IMWRITE_JPEG_QUALITY, 75])
                        await _broadcast(json.dumps({
                            "type": "FRAME", "camera_id": cam_id,
                            "data": base64.b64encode(buf).decode(),
                            "ts": now, "state": analyser.cam_state_label(),
                        }))
                    continue

                # ── CV inference — per-camera executor (no cross-camera blocking) ─
                frame_out, events = await loop.run_in_executor(
                    cam_executor, analyser.process, frame)

                # ── Broadcast alerts ──────────────────────────────────────────
                for ev in events:
                    if _analytics.get(cam_id):
                        _analytics[cam_id]["alerts"] += 1
                        _analytics[cam_id]["zone_risk"] = _worst_risk(
                            _analytics[cam_id]["zone_risk"], ev["severity"])

                    # ── Snapshot: save frame JPG for Telegram photo alerts ────
                    if ev.get("severity", "").upper() in _SNAPSHOT_SEVERITIES:
                        try:
                            snap_name = (f"{cam_id}_{ev.get('rule_id','EVT')}_"
                                         f"{int(now)}.jpg")
                            snap_path = os.path.join(_SNAPSHOT_DIR, snap_name)
                            cv2.imwrite(snap_path, frame_out,
                                        [cv2.IMWRITE_JPEG_QUALITY, 88])
                            ev["snapshot_path"] = snap_path
                            # Keep snapshot folder tidy — remove files older than 1 hour
                            _prune_snapshots(_SNAPSHOT_DIR, max_age_sec=3600)
                        except Exception:
                            pass  # snapshot failure never blocks alert

                    if _broadcast:
                        await _broadcast(json.dumps(ev))

                # ── Broadcast frame ───────────────────────────────────────────
                if now - last_broadcast >= broadcast_ivl:
                    last_broadcast = now
                    small = cv2.resize(frame_out, (640, 360), interpolation=cv2.INTER_AREA)
                    _, buf = cv2.imencode('.jpg', small, [cv2.IMWRITE_JPEG_QUALITY, 82])
                    if _broadcast:
                        await _broadcast(json.dumps({
                            "type": "FRAME", "camera_id": cam_id,
                            "data": base64.b64encode(buf).decode(), "ts": now,
                            "state": analyser.cam_state_label(),
                        }))

                # ── Periodic FPS + analytics snapshot ────────────────────────
                if int(now) % 10 == 0 and int(now) != analyser.last_snap_ts:
                    analyser.last_snap_ts = int(now)
                    elapsed = now - _fps_window_ts
                    if elapsed > 0:
                        _camera_fps[cam_id] = round(_fps_count / elapsed, 1)
                    _fps_count     = 0
                    _fps_window_ts = now
                    if _broadcast:
                        await _broadcast(json.dumps(get_analytics_snapshot()))

                await asyncio.sleep(0.001)

        except asyncio.CancelledError:
            break
        except Exception as exc:
            await _set_status(cam_id, CameraStatus.ERROR, str(exc))
        finally:
            if cap:
                cap.release()
            if rtsp_reader:
                rtsp_reader.stop()
                _rtsp_readers.pop(cam_id, None)

        # RTSP/WEBCAM: reconnect; FILE stops here
        if cfg.source in (CameraSource.RTSP, CameraSource.WEBCAM) and not cfg.stopped:
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
        else:
            break

    _analysers.pop(cam_id, None)
    if not _cameras.get(cam_id):
        return
    if _cameras[cam_id].status not in (CameraStatus.ERROR, CameraStatus.OFFLINE):
        await _set_status(cam_id, CameraStatus.OFFLINE)


def _worst_risk(current, new_sev):
    order = {"LOW":0,"MEDIUM":1,"HIGH":2,"CRITICAL":3}
    return new_sev if order.get(new_sev,0) > order.get(current,0) else current

async def _set_status(cam_id, status, error=""):
    cfg = _cameras.get(cam_id)
    if not cfg: return
    cfg.status = status
    cfg.error_msg = error
    if _broadcast:
        await _broadcast(json.dumps({
            "type": "CAM_STATUS", "camera_id": cam_id,
            "status": status.value, "error": error,
        }))


# ══════════════════════════════════════════════════════════════════════════════
#  FRAME ANALYSER  — core CV + behavioural rule engine
# ══════════════════════════════════════════════════════════════════════════════
class FrameAnalyser:
    _BASE_W = 640.0

    # ── Detection ─────────────────────────────────────────────────────────────
    MIN_BLOB_AREA   = 500
    MIN_PERSON_H    = 25
    WARMUP_FRAMES   = 5     # almost immediate — fire rules after 5 frames
    MIN_TRACK_POS   = 3     # only need 3 positions to evaluate a track
    MIN_TRACK_SEC   = 0.1   # mature in 0.1s — near instant

    # ── Velocity base (px/s at 640px width) — scaled in _calibrate() ─────────
    VEL_WALK    = 30
    VEL_RUN     = 70
    VEL_FLEE    = 130
    VEL_SPRINT  = 220

    # ── Temporal windows (seconds a condition must be continuously true) ───────
    # Longer window = fewer false positives. Tune up when false positive rate rises.
    TW = {
        "CRM-001": 1.0,   # snatching — allow 1s for quick event
        "CRM-002": 1.2,   # assault — slightly more sustained
        "CRM-003": 1.5,   # robbery
        "CRM-004": 6.0,   # pickpocket — sustained close contact
        "CRM-007": 10.0,  # stalking — must follow for 10s
        "CRM-008": 1.0,   # kidnapping
        "CRM-009": 1.5,   # domestic violence
        "CRM-010": 3.0,   # distraction theft setup
        "CRM-011": 2.0,   # group fight
        "CRM-013": 55.0,  # casing — very long stationary
        "CRM-014": 3.0,   # mob
        "CRM-015": 2.5,   # fleeing — must sustain high speed longer
        "CRM-016": 1.2,   # sudden accel — must persist 1.2s not just one frame
        "SEC-001": 70.0,  # loitering — 70s before alert
        "SEC-002": 1.5,   # rushing
        "SEC-003": 2.0,   # after-hours restricted zone
        "SEC-005": 2.0,   # restricted zone — must stay in zone 2s
        "SEC-006": 5.0,   # suspicious repeated gestures
        "SEC-008": 3.0,   # running — 3s sustained
        "SEC-009": 3.0,   # after hours
        "SEC-011": 4.0,   # coordinated group
        "SEC-012": 15.0,  # perimeter encroachment
        "SEC-014": 2.5,   # confrontation
        "CRW-001": 4.0,   # crowd density — must persist 4s
        "CRW-004": 2.5,   # fallen
        "BIZ-003": 70.0,  # product dwell
        "BIZ-004": 6.0,   # queue
        # BEH rules — significantly tightened to suppress false positives
        "BEH-001": 35.0, "BEH-003": 25.0, "BEH-010": 15.0,
        "BEH-012": 25.0, "BEH-017": 28.0,
        "BEH-018": 2.0,  "BEH-022": 200.0,"BEH-026": 12.0, "BEH-027": 150.0,
        # ANO rules — increased from 0.5s to require sustained anomaly
        "ANO-001": 7.0,  "ANO-004": 7.0,  "ANO-009": 2.5,
        "ANO-019": 2.5,  "ANO-027a": 12.0,"ANO-034": 2.0, "ANO-035": 12.0,
        # SYS rules
        "SYS-002": 8.0,
        # MOG2 fallback — fires after 2s sustained high motion
        "_MOG2_ACTIVITY": 2.0,
    }

    # ── Per-camera rate limits (max alerts per severity per 60 s) ─────────────
    # Tightened: fewer allowed alerts per minute to prevent alert storms.
    RATE_WINDOW = 60
    RATE_LIMITS = {"CRITICAL": 8, "HIGH": 6, "MEDIUM": 8, "LOW": 15}

    # ── Weighted confidence system ─────────────────────────────────────────────
    # Rules are suppressed when the composite confidence score < CONF_THRESHOLD.
    # Weights: (detection, tracking, motion, temporal, context) — must sum to 1.0
    CONF_THRESHOLD = 0.65   # lowered from 0.82 → allows alerts to fire on realistic footage
    CONF_WEIGHTS: Dict[str, Tuple] = {
        "CRIME":    (0.25, 0.18, 0.22, 0.20, 0.15),
        "SECURITY": (0.18, 0.20, 0.15, 0.27, 0.20),
        "BEHAVIOR": (0.15, 0.22, 0.10, 0.35, 0.18),
        "ANOMALY":  (0.22, 0.18, 0.25, 0.18, 0.17),
        "BUSINESS": (0.18, 0.18, 0.12, 0.30, 0.22),
        "CROWD":    (0.20, 0.20, 0.20, 0.20, 0.20),
        "STAFF":    (0.20, 0.20, 0.20, 0.20, 0.20),
        "SYSTEM":   (0.12, 0.10, 0.10, 0.38, 0.30),
    }

    # ── Rule cooldowns (per key, seconds) ─────────────────────────────────────
    CD = {
        "CRM-001":45,"CRM-002":40,"CRM-003":40,"CRM-004":60,
        "CRM-007":60,"CRM-008":45,"CRM-009":45,"CRM-010":60,
        "CRM-011":40,"CRM-013":90,
        "CRM-014":45,"CRM-015":45,"CRM-016":45,
        "SEC-001":120,"SEC-002":45,"SEC-003":60,
        "SEC-005":60,"SEC-006":90,"SEC-008":45,"SEC-009":60,
        "SEC-011":60,"SEC-012":90,"SEC-014":45,
        "CRW-001":60,"CRW-004":45,
        "BIZ-001":60,"BIZ-003":120,"BIZ-004":90,
        # BEH cooldowns — raised to suppress repeat storms
        "BEH-001":120,"BEH-003":120,"BEH-010":120,
        "BEH-012":120,"BEH-017":180,"BEH-018":120,
        "BEH-022":300,"BEH-026":90, "BEH-027":180,
        # ANO cooldowns — raised to suppress frequent re-fires
        "ANO-001":120,"ANO-004":90, "ANO-009":90, "ANO-019":90,
        "ANO-027a":90,"ANO-034":60, "ANO-035":120,
        # SYS cooldowns — 003/006 raised to 3600s to avoid spam during demo
        "SYS-002":120,"SYS-003":3600,"SYS-005":300,"SYS-006":3600,
    }

    # ── Distance base (px at 640px width) ─────────────────────────────────────
    DIST_SNATCH = 110
    DIST_FIGHT  = 80
    DIST_FOLLOW = 140
    DIST_CROWD  = 120

    def __init__(self, cam_id, cam_name, zone):
        self.cam_id       = cam_id
        self.cam_name     = cam_name
        self.zone         = zone
        self.frame_n      = 0
        self.last_snap_ts = 0
        self._calibrated  = False
        self._use_yolo    = _YOLODet.ensure()   # try once at startup
        self._kps_map:    Dict[str, Optional[np.ndarray]] = {}  # uid → keypoints
        self._pending_kps: List[Tuple] = []  # [(bbox, kps), ...] per frame

        self.bg_sub = cv2.createBackgroundSubtractorMOG2(
            history=120, varThreshold=16, detectShadows=False)

        self.tracks:       Dict[str, PersonTrack] = {}
        self.next_id       = 0
        self.prev_gray:    Optional[np.ndarray]   = None
        self.fired:        Dict[str, float]       = {}
        self.entry_y:      Optional[int]          = None
        self.scene_triggers: dict                 = {}
        self.rate_log:     Dict[str, list]        = {
            "CRITICAL":[], "HIGH":[], "MEDIUM":[], "LOW":[]
        }
        # YOLO detection confidence per track UID (0.40–1.0); 0.65 when using MOG2
        self._det_conf:    Dict[str, float]       = {}

        # Zone fractions of frame
        self.checkout_zone    = (0.60, 0.60, 1.0, 1.0)
        self.restricted_zone  = (0.75, 0.00, 1.0, 0.35)

        # State-based alert engine (scene-level)
        self.scene_alert_active: Set[str] = set()

        # Interaction engine: pair_key → timestamp when proximity started
        self._interaction_start: Dict[str, float] = {}

        # ── Adaptive load control ─────────────────────────────────────────────
        self._proc_times: deque = deque(maxlen=30)
        self._skip_n:     int   = 1

        # ANO / SYS analytics state
        self._count_history:   List[Tuple[float, int]] = []
        self._vel_baseline:    Dict[int, List[float]]  = {h: [] for h in range(24)}
        self._prev_brightness: Optional[float]         = None
        self._alert_history:   List[float]             = []
        self._last_sys_check:  float                   = 0.0
        self._fps_window_start: float                  = time.time()
        self._fps_frame_count:  int                    = 0

        # Rule engine — primary decision system
        self._rule_engine = RuleEngine(self)

    def _mog2_detect(self, frame: np.ndarray) -> Tuple[List[Tuple], List]:
        fg = self.bg_sub.apply(frame)
        # Smaller morph kernels → less blob merging when people are close together
        fg = cv2.morphologyEx(fg, cv2.MORPH_CLOSE,
             cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (5, 5)))
        fg = cv2.morphologyEx(fg, cv2.MORPH_OPEN,
             cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3)))
        cnts, _ = cv2.findContours(fg, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        blobs = []
        for c in cnts:
            area = cv2.contourArea(c)
            if area < self.MIN_BLOB_AREA: continue
            x, y, bw, bh = cv2.boundingRect(c)
            if bh < self.MIN_PERSON_H: continue
            # Split very wide blobs — likely two merged persons side by side
            if bw > bh * 1.8 and bw > 80:
                half = bw // 2
                blobs.append((x,      y, half, bh))
                blobs.append((x+half, y, half, bh))
            else:
                blobs.append((x, y, bw, bh))
        # Use low IoU threshold (0.20) so nearby people aren't merged by NMS
        blobs = _nms(blobs, 0.20)
        return blobs, [None] * len(blobs)

    def reset_tracks(self):
        """Clear all tracks on video loop — prevents stale state carrying over."""
        self.tracks.clear()
        self.scene_triggers.clear()
        self.fired.clear()
        self.scene_alert_active.clear()
        self._interaction_start.clear()
        self.next_id = 0
        self._rule_engine.reset()

    def reset_bg(self):
        """Re-initialise the background subtractor on each video loop.
        Without this the MOG2 model learns the video's own motion as 'background'
        after 2-3 loops and stops detecting anything.
        """
        self.bg_sub = cv2.createBackgroundSubtractorMOG2(
            history=120, varThreshold=16, detectShadows=False)
        self.frame_n = 0       # restart warmup so BG model re-learns from scratch
        self.prev_gray = None  # clear optical flow state

    def cam_state_label(self) -> str:
        # Show warmup progress while the background model is still learning
        if self.frame_n < self.WARMUP_FRAMES:
            pct = int(self.frame_n / self.WARMUP_FRAMES * 100)
            return f"ANALYSING {pct}%"
        active = [t for t in self.tracks.values()
                  if time.time() - t.last_seen < 2.0]
        n = len(active)
        if n == 0: return "CLEAR"
        states = [t.state.value for t in active]
        if "FLEEING"  in states: return "ALERT"
        if "RUNNING"  in states: return "ACTIVE"
        if "FALLEN"   in states: return "EMERGENCY"
        return f"{n} PERSON{'S' if n>1 else ''}"

    # ── Calibrate pixel thresholds to frame size ───────────────────────────────
    def _calibrate(self, W: int, H: int):
        if self._calibrated: return
        s = W / self._BASE_W
        self.VEL_WALK    = max(18,  int(30  * s))
        self.VEL_RUN     = max(45,  int(70  * s))
        self.VEL_FLEE    = max(85,  int(130 * s))
        self.VEL_SPRINT  = max(130, int(220 * s))
        self.DIST_SNATCH = max(60,  int(110 * s))
        self.DIST_FIGHT  = max(45,  int(80  * s))
        self.DIST_FOLLOW = max(70,  int(140 * s))
        self.DIST_CROWD  = max(80,  int(120 * s))
        self.MATCH_DIST  = max(50,  int(90  * s))
        self.LOITER_DISP = max(20,  int(35  * s))
        self._calibrated = True

    # ── Main process ──────────────────────────────────────────────────────────
    def process(self, frame: np.ndarray):
        _proc_start = time.time()
        self.frame_n += 1

        # Performance: resize to 640×360 before any inference
        frame = cv2.resize(frame, (640, 360), interpolation=cv2.INTER_LINEAR)

        H, W = frame.shape[:2]
        self._calibrate(W, H)
        if self.entry_y is None:
            self.entry_y = int(H * 0.18)
        now = time.time()

        # Step 1 — detect persons (YOLO preferred, MOG2 fallback)
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        # Pose every 3rd frame to halve keypoint inference cost
        _use_pose_this_frame = (self.frame_n % 3 == 1)

        if _use_pose_this_frame:
            _yolo_boxes, _yolo_kps = _YOLODet.detect_pose(frame)
        else:
            _yolo_boxes, _yolo_kps = None, None

        if _yolo_boxes is not None:
            blobs     = _yolo_boxes
            _kps_raw  = _yolo_kps
        elif self._use_yolo:
            _det = _YOLODet.detect(frame)
            if _det is not None:
                blobs    = _det
                _kps_raw = [None] * len(blobs)
            else:
                self._use_yolo = False  # disable if detect fails
                blobs, _kps_raw = self._mog2_detect(frame)
        else:
            blobs, _kps_raw = self._mog2_detect(frame)

        # Keep keypoints indexed by centroid for later assignment
        self._pending_kps = list(zip(blobs, _kps_raw)) if _kps_raw else []

        # Step 2 — update tracks (capture YOLO per-bbox confidence, fall back to 0.65 for MOG2)
        self._last_frame = frame          # kept for crop sampling
        _blob_confs = list(_YOLODet._last_confs) if _YOLODet._last_confs else [0.65] * len(blobs)
        if len(_blob_confs) < len(blobs):          # safety: pad if lengths diverge
            _blob_confs += [0.65] * (len(blobs) - len(_blob_confs))
        centroids = [(x+w//2, y+h//2, x, y, w, h) for x,y,w,h in blobs]
        self._update_tracks(centroids, now, W, H, _blob_confs)

        # Periodic detection diagnostic — every 30 frames shows what YOLO/MOG2 sees
        if self.frame_n % 30 == 1:
            src = "YOLO" if (_yolo_boxes is not None or self._use_yolo) else "MOG2"
            print(f"[DET] frame={self.frame_n} src={src} blobs={len(blobs)} "
                  f"tracks={len(self.tracks)} "
                  f"active={len([t for t in self.tracks.values() if now-t.last_seen<2.0])}",
                  flush=True)

        # Step 2b — assign keypoints to tracks (nearest centroid match)
        if self._pending_kps:
            for uid, t in self.tracks.items():
                if now - t.last_seen > 0.5: continue
                cx, cy = t.last_pos()
                best_kps, best_d = None, float("inf")
                for (bx,by,bw,bh), kps in self._pending_kps:
                    bcx, bcy = bx+bw//2, by+bh//2
                    d = math.hypot(cx-bcx, cy-bcy)
                    if d < best_d:
                        best_d, best_kps = d, kps
                if best_d < getattr(self, "MATCH_DIST", 90):
                    self._kps_map[uid] = best_kps

        # Step 3 — optical flow velocity refinement every 3rd frame
        if self.prev_gray is not None and self.frame_n % 3 == 0:
            self._flow_refine(gray, now)
        self.prev_gray = gray

        # Step 4 — classify human states
        active = [t for t in self.tracks.values() if now - t.last_seen < 2.0]
        for t in active:
            self._classify_state(t, now)

        if _analytics.get(self.cam_id):
            _analytics[self.cam_id]["active"] = len(active)

        # Step 5 — Rule Engine (PRIMARY decision system)
        events: List[dict] = []
        if self.frame_n > self.WARMUP_FRAMES:
            mature = [t for t in active
                      if len(t.positions) >= self.MIN_TRACK_POS
                      and t.dwell_sec() >= self.MIN_TRACK_SEC]

            _pdebug(
                f"{self.cam_id} frame={self.frame_n} "
                f"blobs={len(blobs)} active={len(active)} mature={len(mature)} "
                f"yolo={self._use_yolo} "
                + (f"vels=[{','.join(str(int(t.smooth_velocity(0.6))) for t in active)}]"
                   if active else "")
            )

            # ── Primary: rule engine evaluates ALL behavioural rules ──────────
            _scene_features = self._rule_engine.extract_features(
                active, mature, W, H, now)
            events.extend(self._rule_engine.evaluate_all(_scene_features, now))

            # Update BIZ-004 queue analytics counter
            if _analytics.get(self.cam_id) and _scene_features.persons:
                _analytics[self.cam_id]["queue"] = sum(
                    1 for p in _scene_features.persons if p.in_checkout)

            # ── Non-rule-engine modules: entry counting, anomaly, system ─────
            ev = self._entry_crossing(active, now)
            if ev: events.append(ev)

            events.extend(self._anomaly_rules(
                active, len(active), W, H, now, gray, len(events)))
            events.extend(self._sys_rules(now, gray))

            # ── MOG2 fallback: direct pixel-motion alert (fires when YOLO unavailable) ──
            # Detects high-intensity physical activity without needing track pairs.
            # Works purely on the foreground mask pixel density and blob velocity.
            if not self._use_yolo:
                ev = self._mog2_activity_alert(active, now, W, H)
                if ev:
                    events.append(ev)

            # ── Single-person violence detector (always active, YOLO or MOG2) ──
            # Catches fights where only one combatant is visible in frame.
            # Fires CRM-FIGHT "Fight / Physical Violence Detected" (CRITICAL).
            ev = self._single_person_violence_alert(active, now)
            if ev:
                events.append(ev)

            # ── Suspicious assault / aggressive behaviour (HIGH, lower bar) ─────
            # Fires earlier than CRM-FIGHT — catches threatening approach,
            # sudden acceleration, aggressive flailing before punch lands.
            ev = self._suspicious_assault_alert(active, now)
            if ev:
                events.append(ev)

            # ── Re-ID check: once per new mature track ───────────────────────
            for t in mature:
                if not getattr(t, "_reid_checked", False) and t.frame_crops:
                    t._reid_checked = True  # type: ignore[attr-defined]
                    reid_ev = REID.match(
                        self.cam_id, t.uid, t.frame_crops,
                        t.aspect_ratio(), t.smooth_velocity(1.0))
                    if reid_ev:
                        reid_ev["camera_id"]   = self.cam_id
                        reid_ev["camera_name"] = self.cam_name
                        reid_ev["zone"]        = self.zone
                        events.append(reid_ev)

            # ── Priority filter: CRIME > SECURITY > ANOMALY > BEHAVIOR ───────
            events = self._apply_priority_filter(events)

            if events:
                for ev in events:
                    _pdebug(f"  *** ALERT FIRED: {ev.get('rule_id')} "
                            f"{ev.get('severity')} — {ev.get('rule_name')}")
            elif _PIPE_DEBUG and self.frame_n % 30 == 0:
                _pdebug(f"  (no alerts this frame)")

        # Step 6 — draw overlay
        out = self._draw(frame, active, blobs, W, H, events)

        # Record processing time and update adaptive load control
        self._proc_times.append(time.time() - _proc_start)
        self._update_load_control()

        return out, events

    # ── Human state classifier (keypoint-aware) ───────────────────────────────
    def _classify_state(self, t: PersonTrack, now: float):
        vel = t.smooth_velocity(0.6)
        ar  = t.aspect_ratio()

        # ── Try YOLO-pose keypoint classification first ───────────────────────
        kps = self._kps_map.get(t.uid)
        if kps is not None:
            new_state = self._classify_from_keypoints(kps, vel)
            if new_state is not None:
                if new_state != t.state:
                    t.state    = new_state
                    t.state_ts = now
                return

        # ── Geometric fallback (improved) ─────────────────────────────────────
        # Fallen: wide bbox + low speed + mature track
        if ar > 2.2 and vel < self.VEL_RUN * 0.4 and t.dwell_sec() > 1.5:
            new_state = HumanState.FALLEN
        elif vel >= self.VEL_FLEE:
            new_state = HumanState.FLEEING
        elif vel >= self.VEL_RUN:
            new_state = HumanState.RUNNING
        elif vel >= self.VEL_WALK:
            new_state = HumanState.WALKING
        elif ar > 1.6 and vel < self.VEL_WALK * 0.8:
            new_state = HumanState.SITTING
        elif vel < self.VEL_WALK:
            # Tall bbox but not moving much → STANDING; tiny displacement → IDLE
            disp = t.displacement_px(5.0)
            new_state = HumanState.IDLE if disp < self.LOITER_DISP else HumanState.STANDING
        else:
            new_state = HumanState.STANDING

        if new_state != t.state:
            t.state    = new_state
            t.state_ts = now

    def _classify_from_keypoints(self, kps: np.ndarray, vel: float) -> Optional["HumanState"]:
        """
        YOLO-pose keypoints: 17 points (x, y, conf) in COCO order.
        Indices: 0=nose,5=L-shoulder,6=R-shoulder,11=L-hip,12=R-hip,
                 13=L-knee,14=R-knee,15=L-ankle,16=R-ankle
        """
        try:
            if kps is None or kps.shape[0] < 17:
                return None
            conf_thr = 0.3

            def valid(i):
                return kps[i, 2] > conf_thr

            # Fallen: shoulder y ≈ hip y (all on same horizontal level)
            if valid(5) and valid(6) and valid(11) and valid(12):
                sh_y  = (kps[5,1] + kps[6,1]) / 2
                hip_y = (kps[11,1] + kps[12,1]) / 2
                sh_x  = abs(kps[5,0] - kps[6,0])
                hip_x = abs(kps[11,0] - kps[12,0])
                vert_diff = abs(sh_y - hip_y)
                horiz_span = max(sh_x, hip_x)
                if vert_diff < horiz_span * 0.5 and vel < self.VEL_RUN * 0.4:
                    return HumanState.FALLEN

            # Sitting: hip y is close to knee y (legs bent horizontal)
            if valid(11) and valid(12) and valid(13) and valid(14):
                hip_y  = (kps[11,1] + kps[12,1]) / 2
                knee_y = (kps[13,1] + kps[14,1]) / 2
                # If hips and knees at similar height → sitting
                if abs(hip_y - knee_y) < 20 and vel < self.VEL_WALK:
                    return HumanState.SITTING

            # Velocity-based states
            if vel >= self.VEL_FLEE:  return HumanState.FLEEING
            if vel >= self.VEL_RUN:   return HumanState.RUNNING
            if vel >= self.VEL_WALK:  return HumanState.WALKING
            return None
        except Exception:
            return None

    # ── Temporal gate ──────────────────────────────────────────────────────────
    def _tgate(self, triggers: dict, rule_id: str,
               now: float, gap_tol: float = 0.5) -> bool:
        """
        Accumulate time a rule condition is continuously true.
        Returns True once accumulated time >= TW[rule_id].
        Resets if there's a gap > gap_tol seconds.
        """
        required = self.TW.get(rule_id, 2.0)
        rt = triggers.get(rule_id)
        if rt is None or (now - rt.last_ts) > gap_tol:
            triggers[rule_id] = RuleTrigger(start_ts=now, last_ts=now, hit_count=1)
            return False
        rt.last_ts  = now
        rt.hit_count += 1
        return (rt.last_ts - rt.start_ts) >= required

    def _tgate_reset(self, triggers: dict, rule_id: str):
        triggers.pop(rule_id, None)

    # ── Hard suppression layer (physical reality checks before any scoring) ─────
    # These block rules that are impossible given the current physical state,
    # preventing the confidence system from even evaluating them.
    _MOTION_RULES = frozenset({
        "CRM-015","CRM-016","SEC-008",
        "BEH-017","BEH-018","ANO-009","ANO-019",
    })
    _VELOCITY_RULES = frozenset({
        "CRM-015","CRM-016","SEC-008","BEH-018",
    })
    _CRIME_MULTI_PERSON = frozenset({
        "CRM-001","CRM-002","CRM-003","CRM-004","CRM-007",
        "CRM-008","CRM-011","CRM-014","SEC-011","SEC-014",
    })
    _INTERACTION_AGGRESSION = frozenset({
        "CRM-001","CRM-002","CRM-011","CRM-014","SEC-014",
    })

    def _hard_suppress(self, rule_id: str,
                       t: Optional["PersonTrack"],
                       n_active: int, now: float) -> bool:
        """
        Return True if the rule should be hard-blocked regardless of confidence.

        Conditions:
          1. SITTING state → block all motion/behavior alerts (not FALLEN response CRW-004)
          2. Pose stable ≥3s (tiny displacement) → block motion rules
          3. Velocity < WALK threshold → block velocity-based running/fleeing rules
          4. Single person in scene → block multi-person crime rules
          5. No nearby person within 2s interaction window → block aggression/theft rules
        """
        if t is None:
            # scene-level rules: only block CRIME_MULTI if alone
            if rule_id in self._CRIME_MULTI_PERSON and n_active < 2:
                return True
            return False

        state = t.state
        vel   = t.smooth_velocity(0.6)

        # 1. SITTING → suppress all motion alerts (guard: allow CRW-004 fallen-person check)
        if state == HumanState.SITTING and rule_id != "CRW-004":
            if rule_id in self._MOTION_RULES:
                return True

        # 2. Pose stable for ≥3s (displacement < half loiter threshold) → block motion alerts
        if rule_id in self._MOTION_RULES:
            disp = t.displacement_px(3.0)
            if disp < getattr(self, "LOITER_DISP", 35) * 0.5:
                return True

        # 3. Low velocity → block rules that require running / fleeing speed
        if rule_id in self._VELOCITY_RULES and vel < self.VEL_WALK:
            return True

        # 4. Single person → block multi-person crime rules
        if rule_id in self._CRIME_MULTI_PERSON and n_active < 2:
            return True

        # 5. No nearby person (interaction proximity check) → block aggression/theft
        if rule_id in self._INTERACTION_AGGRESSION:
            active = [tr for tr in self.tracks.values()
                      if now - tr.last_seen < 2.0 and tr.uid != t.uid]
            if not active:
                return True
            cx, cy = t.last_pos()
            nearest = min(
                math.hypot(cx - tr.last_pos()[0], cy - tr.last_pos()[1])
                for tr in active
            )
            if nearest > getattr(self, "DIST_FIGHT", 80) * 2.5:
                return True

        # 6. Erratic / behavior rules: require real motion variance (not sensor noise)
        _ERRATIC_RULES = frozenset({"BEH-017", "BEH-001", "BEH-012"})
        if rule_id in _ERRATIC_RULES:
            var = self._motion_variance(t, 5.0)
            if var < 120.0:   # (px/s)² — block if speed is too uniform (false noise)
                return True

        return False

    # ── Weighted confidence system ─────────────────────────────────────────────
    def _confidence(self, rule_id: str, category: str,
                    t: Optional["PersonTrack"], now: float) -> float:
        """
        Compute composite confidence (0–1) for a person-level rule.

        Five independent signals, weighted by rule category:
          1. detection_conf  — YOLO confidence (exponentially smoothed per track)
          2. tracking_conf   — track maturity (position count + age)
          3. motion_conf     — velocity signal strength relative to walk baseline
          4. temporal_conf   — how long past the temporal window threshold
          5. context_conf    — environment factors (zone, time, interaction context)

        final_score = Σ weight[i] * signal[i]
        Alert fires only if final_score >= CONF_THRESHOLD (default 0.72).
        """
        w = self.CONF_WEIGHTS.get(category, (0.20, 0.20, 0.20, 0.20, 0.20))

        # 1. Detection confidence — YOLO bbox score (0.40–1.0) or MOG2 proxy 0.65
        det_c = self._det_conf.get(t.uid, 0.65) if t else 0.65

        # 2. Tracking confidence — how mature / stable the track is
        if t:
            pos_c = min(1.0, len(t.positions) / 38.0)   # 38 positions → full confidence
            age_c = min(1.0, t.dwell_sec() / 5.0)       # 5 s age → full confidence
            trk_c = (pos_c + age_c) * 0.5
        else:
            trk_c = 0.55

        # 3. Motion confidence — velocity signal vs walk baseline
        if t:
            vel   = t.smooth_velocity(0.6)
            mot_c = min(1.0, vel / max(self.VEL_WALK * 0.8, 1.0))
        else:
            mot_c = 0.55

        # 4. Temporal confidence — fraction of temporal window elapsed past threshold
        triggers = t.triggers if t else self.scene_triggers
        rt = triggers.get(rule_id)
        if rt:
            required = self.TW.get(rule_id, 2.0)
            elapsed  = rt.last_ts - rt.start_ts
            tmp_c    = min(1.0, elapsed / max(required * 0.75, 0.05))
        else:
            tmp_c = 0.50

        # 5. Context confidence — environmental and scene-level multipliers
        ctx_c = self._context_conf(rule_id, category, t, now)

        score = (w[0] * det_c + w[1] * trk_c + w[2] * mot_c
                 + w[3] * tmp_c + w[4] * ctx_c)
        return round(min(1.0, max(0.0, score)), 4)

    def _scene_confidence(self, rule_id: str, category: str, now: float) -> float:
        """
        Composite confidence for scene-level (group) rules — no single track anchor.
        Uses aggregate signals across all active mature tracks.
        """
        w = self.CONF_WEIGHTS.get(category, (0.20, 0.20, 0.20, 0.20, 0.20))

        # 1. Detection — YOLO gives higher overall quality than MOG2
        det_c = 0.82 if self._use_yolo else 0.62

        # 2. Tracking — proportion of mature tracks in the scene
        active = [t for t in self.tracks.values() if now - t.last_seen < 2.0]
        mature_n = sum(1 for t in active if len(t.positions) >= self.MIN_TRACK_POS)
        trk_c = min(1.0, mature_n / max(len(active), 1))

        # 3. Motion — scene-average normalised velocity
        vels = [t.smooth_velocity(0.6) for t in active]
        if vels:
            avg_vel = sum(vels) / len(vels)
            mot_c   = min(1.0, avg_vel / max(self.VEL_WALK * 0.8, 1.0))
        else:
            mot_c = 0.50

        # 4. Temporal — scene-trigger accumulation
        rt = self.scene_triggers.get(rule_id)
        if rt:
            required = self.TW.get(rule_id, 2.0)
            elapsed  = rt.last_ts - rt.start_ts
            tmp_c    = min(1.0, elapsed / max(required * 0.75, 0.05))
        else:
            tmp_c = 0.50

        # 5. Context
        ctx_c = self._context_conf(rule_id, category, None, now)

        score = (w[0] * det_c + w[1] * trk_c + w[2] * mot_c
                 + w[3] * tmp_c + w[4] * ctx_c)
        return round(min(1.0, max(0.0, score)), 4)

    def _context_conf(self, rule_id: str, category: str,
                      t: Optional["PersonTrack"], now: float) -> float:
        """
        Context-aware confidence component (0–1).
        Boosts: after-hours crime/security, restricted-zone presence.
        Suppresses: single-person scene for interaction rules.
        """
        ctx = 0.62  # neutral base

        h = int(time.strftime("%H"))
        is_after_hours = (h >= 22 or h < 7)
        n_active = sum(1 for tr in self.tracks.values()
                       if now - tr.last_seen < 2.0)

        # Time-of-day boost for crime and security rules
        if category in ("CRIME", "SECURITY") and is_after_hours:
            ctx += 0.18

        # Zone boost — person in restricted area strengthens security/crime confidence
        if t is not None and hasattr(self, "_last_WH"):
            W, H = self._last_WH
            cx, cy = t.last_pos()
            rx1, ry1, rx2, ry2 = self.restricted_zone
            if (rx1 * W <= cx <= rx2 * W) and (ry1 * H <= cy <= ry2 * H):
                if category in ("SECURITY", "CRIME"):
                    ctx += 0.14

        # Suppress interaction rules when there is only one person
        _INTERACTION_RULES = frozenset({
            "CRM-001", "CRM-002", "CRM-003", "CRM-007", "CRM-008",
            "CRM-011", "CRM-014", "SEC-011", "SEC-014",
        })
        if rule_id in _INTERACTION_RULES and n_active < 2:
            ctx -= 0.28

        # Anomaly confidence rises with erratic movement
        if t is not None and category == "ANOMALY":
            dir_ch = self._direction_changes(t, 10.0)
            ctx   += min(0.18, dir_ch * 0.025)

        return max(0.0, min(1.0, ctx))

    ASSAULT_INTENT_THRESHOLD = 0.48  # lowered from 0.72 — grappling fights have low vel_sig but high chaos_sig

    # ── Rate limiter ───────────────────────────────────────────────────────────
    def _rate_ok(self, severity: str, now: float) -> bool:
        sev = severity if severity in self.rate_log else "MEDIUM"
        cutoff = now - self.RATE_WINDOW
        self.rate_log[sev] = [t for t in self.rate_log[sev] if t > cutoff]
        if len(self.rate_log[sev]) >= self.RATE_LIMITS.get(sev, 10):
            return False
        self.rate_log[sev].append(now)
        return True

    # ── Fire helpers ──────────────────────────────────────────────────────────
    def _fire(self, rule_id, uid, score, now,
              category, severity, name, desc, trigger, action, reasons):
        key = f"{rule_id}:{uid}"
        if now - self.fired.get(key, 0) < self.CD.get(rule_id, 60):
            return None
        if not self._rate_ok(severity, now):
            return None

        t     = self.tracks.get(uid)
        n_act = sum(1 for tr in self.tracks.values() if now - tr.last_seen < 2.0)

        # ── Hard suppression — block physically impossible alerts first ────
        if self._hard_suppress(rule_id, t, n_act, now):
            return None

        # ── State-based de-dup — fire only on INACTIVE → ACTIVE transition ─
        # If rule_id was already active (fired while condition continuously true),
        # only allow a re-fire after the condition went False (tgate was reset,
        # removing rule_id from t.triggers).
        if t is not None:
            if rule_id in t.alert_active:
                if rule_id in t.triggers:
                    return None   # still active, condition never went False
                else:
                    t.alert_active.discard(rule_id)   # condition reset → allow new fire

        # ── Weighted confidence gate ───────────────────────────────────────
        conf = self._confidence(rule_id, category, t, now)
        if conf < self.CONF_THRESHOLD:
            return None

        if t is not None:
            t.alert_active.add(rule_id)
        self.fired[key] = now
        s = max(1, min(99, int(conf * 99)))
        return _evt(rule_id, name, category, severity, s, uid,
                    self.cam_id, self.cam_name, self.zone,
                    desc, trigger, action, reasons)

    def _fire2(self, rule_id, score, now,
               category, severity, name, desc, trigger, action, reasons):
        if now - self.fired.get(rule_id, 0) < self.CD.get(rule_id, 60):
            return None
        if not self._rate_ok(severity, now):
            return None

        n_act = sum(1 for tr in self.tracks.values() if now - tr.last_seen < 2.0)

        # ── Hard suppression (scene-level) ────────────────────────────────
        if self._hard_suppress(rule_id, None, n_act, now):
            return None

        # ── State-based de-dup (scene-level, keyed by rule_id directly) ───
        # Applies only to rules that use rule_id (not pair-suffixed) as tgate key.
        # Pair rules (CRM-001:{pair}) still rely on cooldown for dedup.
        if rule_id in self.scene_alert_active:
            if rule_id in self.scene_triggers:
                return None   # condition still active
            else:
                self.scene_alert_active.discard(rule_id)   # condition reset

        # ── Weighted confidence gate (scene-level) ────────────────────────
        conf = self._scene_confidence(rule_id, category, now)
        if conf < self.CONF_THRESHOLD:
            return None

        self.scene_alert_active.add(rule_id)
        self.fired[rule_id] = now
        s = max(1, min(99, int(conf * 99)))
        return _evt(rule_id, name, category, severity, s, "GROUP",
                    self.cam_id, self.cam_name, self.zone,
                    desc, trigger, action, reasons)

    # ── Track management ───────────────────────────────────────────────────────
    def _update_tracks(self, centroids, now, W, H, blob_confs: Optional[List[float]] = None):
        self._last_WH = (W, H)
        unmatched = list(range(len(centroids)))
        match_dist = getattr(self, "MATCH_DIST", int(90 * W / self._BASE_W))
        _confs = blob_confs or []

        for uid, t in list(self.tracks.items()):
            if not centroids: break
            lx, ly = t.last_pos()
            best_i, best_d = -1, float("inf")
            for i in unmatched:
                cx, cy = centroids[i][0], centroids[i][1]
                d = math.hypot(cx-lx, cy-ly)
                if d < best_d:
                    best_d, best_i = d, i
            if best_i >= 0 and best_d < match_dist:
                cx,cy,x,y,bw,bh = centroids[best_i]
                t.last_seen = now
                t.positions.append((cx, cy, now))
                t.bboxes.append((x, y, bw, bh))
                # Update detection confidence with exponential smoothing
                if best_i < len(_confs):
                    prev = self._det_conf.get(uid, _confs[best_i])
                    self._det_conf[uid] = round(prev * 0.7 + _confs[best_i] * 0.3, 3)
                unmatched.remove(best_i)
                # Sample a frame crop every ~30 frames for re-ID (max 8 crops)
                if hasattr(self, "_last_frame") and len(t.frame_crops) < 8:
                    if self.frame_n % 30 == 0:
                        try:
                            H0, W0 = self._last_frame.shape[:2]
                            x1c = max(0, x); y1c = max(0, y)
                            x2c = min(W0, x+bw); y2c = min(H0, y+bh)
                            if (x2c-x1c) > 10 and (y2c-y1c) > 10:
                                crop = self._last_frame[y1c:y2c, x1c:x2c]
                                t.frame_crops.append(crop.copy())
                        except Exception:
                            pass

        for i in unmatched:
            cx,cy,x,y,bw,bh = centroids[i]
            uid = f"P{self.cam_id[-2:]}{self.next_id:04d}"
            self.next_id += 1
            self.tracks[uid] = PersonTrack(
                uid=uid, first_seen=now, last_seen=now,
                positions=deque([(cx,cy,now)], maxlen=120),
                bboxes=deque([(x,y,bw,bh)], maxlen=30),
                zone_since=now,
            )
            # Store the new-track flag so Re-ID check fires once it's mature
            self.tracks[uid]._reid_checked = False  # type: ignore[attr-defined]
            # Seed detection confidence for new track
            if i < len(_confs):
                self._det_conf[uid] = _confs[i]

        # Retire stale tracks — register exit with Re-ID engine
        for uid in list(self.tracks.keys()):
            t = self.tracks[uid]
            if now - t.last_seen > 3.0:
                d = t.dwell_sec()
                if _analytics.get(self.cam_id):
                    a = _analytics[self.cam_id]
                    a["exits"] += 1
                    a["dwell_sum"] += d
                    a["dwell_cnt"] += 1
                    a["avg_dwell"] = a["dwell_sum"] / a["dwell_cnt"]
                    if t.checkout_visited:
                        a["checkout_exits"] += 1
                # Register with Re-ID engine (non-blocking — uses stored crops)
                if d > 2.0:
                    ar  = t.aspect_ratio()
                    vel = t.smooth_velocity(1.0)
                    REID.register_exit(self.cam_id, self.cam_name, self.zone,
                                       uid, t.frame_crops, ar, vel, d)
                self._kps_map.pop(uid, None)
                self._det_conf.pop(uid, None)
                # Clean up interaction engine entries involving this track
                stale_keys = [k for k in self._interaction_start if uid in k]
                for k in stale_keys:
                    self._interaction_start.pop(k, None)
                del self.tracks[uid]

    def _flow_refine(self, gray, now):
        try:
            pts, uid_map = [], []
            for uid, t in self.tracks.items():
                if t.positions:
                    cx,cy,_ = t.positions[-1]
                    pts.append([[float(cx), float(cy)]])
                    uid_map.append(uid)
            if not pts: return
            p0 = np.array(pts, dtype=np.float32)
            p1, st, _ = cv2.calcOpticalFlowPyrLK(
                self.prev_gray, gray, p0, None,
                winSize=(15,15), maxLevel=2,
                criteria=(cv2.TERM_CRITERIA_EPS|cv2.TERM_CRITERIA_COUNT,10,0.03))
            if p1 is None: return
            for i, uid in enumerate(uid_map):
                if st[i][0] != 1: continue
                nx, ny = int(p1[i][0][0]), int(p1[i][0][1])
                t = self.tracks.get(uid)
                if t and t.positions:
                    ox,oy,ot = t.positions[-1]
                    dt = max(now - ot, 0.001)
                    fv = math.hypot(nx-ox, ny-oy) / dt
                    if fv > self.VEL_RUN * 0.5:
                        t.positions[-1] = (nx, ny, now)
        except Exception:
            pass

    def _in_zone(self, t, zone, W, H):
        if not t.positions: return False
        cx,cy,_ = t.positions[-1]
        x1f,y1f,x2f,y2f = zone
        return (x1f*W <= cx <= x2f*W) and (y1f*H <= cy <= y2f*H)

    def _same_direction(self, a: PersonTrack, b: PersonTrack) -> bool:
        if len(a.positions)<3 or len(b.positions)<3: return False
        ax = a.positions[-1][0] - a.positions[-3][0]
        ay = a.positions[-1][1] - a.positions[-3][1]
        bx = b.positions[-1][0] - b.positions[-3][0]
        by = b.positions[-1][1] - b.positions[-3][1]
        return (ax*bx + ay*by) > 0

    # ── Direction-change counter ───────────────────────────────────────────────
    def _direction_changes(self, t: PersonTrack, window_sec: float = 30.0) -> int:
        now = time.time()
        pts = [(x, y) for x, y, ts in t.positions if now - ts <= window_sec]
        if len(pts) < 4:
            return 0
        changes = 0
        prev_dx = pts[1][0] - pts[0][0]
        for i in range(2, len(pts)):
            dx = pts[i][0] - pts[i-1][0]
            if prev_dx * dx < 0:
                changes += 1
            if abs(dx) > 2:
                prev_dx = dx
        return changes

    # ── Motion stability (variance of per-step speeds over a time window) ────────
    def _motion_variance(self, t: PersonTrack, window_sec: float = 3.0) -> float:
        """
        Returns the variance of instantaneous speeds (px/s)² over the window.
        Low variance → movement is uniform/stable → not genuinely erratic.
        """
        now = time.time()
        pts = [(x, y, ts) for x, y, ts in t.positions if now - ts <= window_sec]
        if len(pts) < 4:
            return 0.0
        speeds = []
        for i in range(1, len(pts)):
            x1, y1, t1 = pts[i-1]
            x2, y2, t2 = pts[i]
            dt = max(t2 - t1, 0.001)
            speeds.append(math.hypot(x2-x1, y2-y1) / dt)
        if not speeds:
            return 0.0
        mean = sum(speeds) / len(speeds)
        return sum((s - mean) ** 2 for s in speeds) / len(speeds)

    # ── Approaching check: are a and b moving toward each other? ─────────────────
    def _approaching(self, a: PersonTrack, b: PersonTrack) -> bool:
        if len(a.positions) < 3 or len(b.positions) < 3:
            return False
        ax1, ay1 = a.positions[-3][0], a.positions[-3][1]
        ax2, ay2 = a.positions[-1][0], a.positions[-1][1]
        bx1, by1 = b.positions[-3][0], b.positions[-3][1]
        bx2, by2 = b.positions[-1][0], b.positions[-1][1]
        prev_dist = math.hypot(ax1 - bx1, ay1 - by1)
        cur_dist  = math.hypot(ax2 - bx2, ay2 - by2)
        return cur_dist < prev_dist * 0.92   # closing by ≥8%

    # ── Interaction engine: proximity sustained > min_sustained seconds ───────────
    # ══ INTERACTION ENGINE ═══════════════════════════════════════════════════════
    # Computes per-pair interaction quality every frame.
    # Crime rules are gated behind interaction.active (sustained proximity ≥ 0.5s)
    # Assault requires interaction.score ≥ threshold AND intent score ≥ 0.85.

    def _compute_interaction(self, a: PersonTrack, b: PersonTrack,
                             pair_key: str, now: float) -> InteractionState:
        """
        Full interaction engine for pair (a, b).

        Signals computed:
          - pixel distance between centroids
          - closing speed (rate of distance change)
          - relative velocity magnitude
          - composite 0-1 interaction score

        The InteractionState is returned and used by all pair-level crime rules.
        """
        ix = InteractionState()
        ax, ay = a.last_pos()
        bx, by = b.last_pos()
        dist = math.hypot(ax - bx, ay - by)
        ix.distance = dist

        # Use DIST_FIGHT * 4.0 so persons 2–3 body-widths apart still register as interacting.
        # Old value (DIST_SNATCH*1.6 = ~176px) was too tight for real fight footage at 640px.
        prox_thresh = getattr(self, "DIST_FIGHT", 80) * 4.0

        if dist >= prox_thresh:
            self._interaction_start.pop(pair_key, None)
            return ix   # out of proximity — inactive

        # Track how long they've been in proximity
        ts = self._interaction_start.get(pair_key)
        if ts is None:
            self._interaction_start[pair_key] = now
            ts = now
        ix.start_ts = ts
        ix.duration = now - ts

        # Closing speed — compare distance 3 positions ago vs now
        if len(a.positions) >= 3 and len(b.positions) >= 3:
            ax_p, ay_p = a.positions[-3][0], a.positions[-3][1]
            bx_p, by_p = b.positions[-3][0], b.positions[-3][1]
            prev_dist = math.hypot(ax_p - bx_p, ay_p - by_p)
            dt = max(now - a.positions[-3][2], 0.001)
            ix.closing_speed = (prev_dist - dist) / dt   # positive = closing
        ix.approaching = ix.closing_speed > 5.0

        # Relative velocity (speed difference between the two tracks)
        va = a.smooth_velocity(0.4)
        vb = b.smooth_velocity(0.4)
        ix.rel_velocity = abs(va - vb)

        # Composite score
        dist_score   = max(0.0, 1.0 - dist / prox_thresh)
        dur_score    = min(1.0, ix.duration / 2.0)
        close_score  = min(1.0, max(0.0, ix.closing_speed / 30.0))
        vel_score    = min(1.0, ix.rel_velocity / max(getattr(self, "VEL_RUN", 70), 1))
        ix.score = round(
            0.35 * dist_score + 0.25 * dur_score +
            0.25 * close_score + 0.15 * vel_score,
            4
        )
        ix.active = ix.duration >= 0.5
        return ix

    # ── Motion classification ─────────────────────────────────────────────────
    def _classify_motion(self, vel: float) -> str:
        """Return 'LOW', 'MEDIUM', or 'HIGH' based on velocity vs walk/run thresholds."""
        if vel < self.VEL_WALK * 0.4:
            return "LOW"
        if vel < self.VEL_RUN * 0.7:
            return "MEDIUM"
        return "HIGH"

    # ── Peak acceleration over a short window ────────────────────────────────
    def _acceleration(self, t: PersonTrack, window_sec: float = 0.6) -> float:
        """Return the maximum speed change (px/s²) observed within window_sec."""
        now = time.time()
        pts = [(x, y, ts) for x, y, ts in t.positions if now - ts <= window_sec]
        if len(pts) < 3:
            return 0.0
        speeds = []
        for i in range(1, len(pts)):
            x1, y1, t1 = pts[i - 1]
            x2, y2, t2 = pts[i]
            dt = max(t2 - t1, 0.001)
            speeds.append(math.hypot(x2 - x1, y2 - y1) / dt)
        if len(speeds) < 2:
            return 0.0
        return max(abs(speeds[i] - speeds[i - 1]) for i in range(1, len(speeds)))

    # ── Motion burst counter ─────────────────────────────────────────────────
    def _motion_burst_count(self, t: PersonTrack, window: float = 1.5) -> int:
        """Count discrete high-speed bursts (speed spikes above VEL_RUN threshold)."""
        now = time.time()
        pts = [(x, y, ts) for x, y, ts in t.positions if now - ts <= window]
        if len(pts) < 3:
            return 0
        threshold = self.VEL_RUN * 0.55
        in_burst = False
        count = 0
        for i in range(1, len(pts)):
            x1, y1, t1 = pts[i - 1]
            x2, y2, t2 = pts[i]
            dt = max(t2 - t1, 0.001)
            spd = math.hypot(x2 - x1, y2 - y1) / dt
            if spd >= threshold and not in_burst:
                in_burst = True
                count += 1
            elif spd < threshold * 0.7:
                in_burst = False
        return count

    # ── Motion chaos score 0–1 ───────────────────────────────────────────────
    def _chaos_score(self, t: PersonTrack, window: float = 2.0) -> float:
        """
        Composite chaos: direction-change rate + velocity spike frequency.
        0 = perfectly smooth motion; 1 = maximum chaos.
        """
        now = time.time()
        pts = [(x, y, ts) for x, y, ts in t.positions if now - ts <= window]
        if len(pts) < 4:
            return 0.0
        # Direction changes normalised by step count
        dir_changes = 0
        prev_dx = pts[1][0] - pts[0][0]
        speeds = []
        for i in range(1, len(pts)):
            dx = pts[i][0] - pts[i - 1][0]
            if prev_dx * dx < 0:
                dir_changes += 1
            if abs(dx) > 1:
                prev_dx = dx
            x1, y1, t1 = pts[i - 1]
            x2, y2, t2 = pts[i]
            dt = max(t2 - t1, 0.001)
            speeds.append(math.hypot(x2 - x1, y2 - y1) / dt)
        dir_rate = min(1.0, dir_changes / max(len(pts) - 1, 1) * 3.0)
        # Velocity spike ratio
        if speeds:
            mean_spd = sum(speeds) / len(speeds)
            spikes = sum(1 for s in speeds if s > mean_spd * 2.0)
            spike_rate = min(1.0, spikes / len(speeds) * 4.0)
        else:
            spike_rate = 0.0
        return round(0.55 * dir_rate + 0.45 * spike_rate, 3)

    # ── Contact detection ────────────────────────────────────────────────────
    def _has_contact(self, a: PersonTrack, b: PersonTrack, dist: float) -> bool:
        """True if bboxes overlap OR centroids within 0.6×DIST_FIGHT."""
        if dist < self.DIST_FIGHT * 0.6:
            return True
        if a.bboxes and b.bboxes:
            ax1, ay1, aw, ah = a.bboxes[-1]
            bx1, by1, bw, bh = b.bboxes[-1]
            if not (ax1 + aw < bx1 or bx1 + bw < ax1 or
                    ay1 + ah < by1 or by1 + bh < ay1):
                return True
        return False

    # ── Assault intent composite score ───────────────────────────────────────
    def _assault_intent_score(self, a: PersonTrack, b: PersonTrack,
                              ix: "InteractionState") -> float:
        """
        Five-signal weighted score [0,1] for CRM-002.
        Fires when score >= ASSAULT_INTENT_THRESHOLD (0.48).
        Chaos and burst are weighted highest so grappling/wrestling fights
        (near-zero centroid velocity) still score above the threshold.
        """
        va = a.smooth_velocity(0.4)
        vb = b.smooth_velocity(0.4)

        # 1. Velocity magnitude (both fast)
        vel_sig = min(1.0, (va + vb) / (self.VEL_RUN * 2.2))

        # 2. Closing speed — are they accelerating toward each other?
        close_sig = min(1.0, max(0.0, ix.closing_speed) / 35.0)

        # 3. Chaos on the more chaotic of the two
        chaos_a = self._chaos_score(a, 1.5)
        chaos_b = self._chaos_score(b, 1.5)
        chaos_sig = max(chaos_a, chaos_b)

        # 4. Motion bursts — repeated strike-like spikes
        burst_sig = min(1.0, max(self._motion_burst_count(a, 1.5),
                                 self._motion_burst_count(b, 1.5)) / 3.0)

        # 5. Interaction quality
        inter_sig = min(1.0, ix.score * 2.0)

        score = (0.10 * vel_sig + 0.20 * close_sig + 0.35 * chaos_sig +
                 0.25 * burst_sig + 0.10 * inter_sig)
        return round(min(1.0, score), 4)

    # ── Normal-behaviour hard pre-gate ───────────────────────────────────────
    def _normal_behavior_block(self, a: PersonTrack, b: PersonTrack,
                               va: float, vb: float,
                               dist: float, ix: "InteractionState") -> bool:
        """
        Returns True when the pair is demonstrably non-violent.
        Blocks ALL assault / robbery rules immediately — avoids false positives
        on normal conversation, slow shopping, stationary chat etc.

        NEVER blocks when people are in physical contact range — grappling,
        wrestling and ground fights have near-zero centroid velocity but are
        absolutely violent events.
        """
        # ── Contact override — if they're touching / body-width apart, never
        #    classify as normal regardless of speed. Grappling fights look
        #    exactly like two people standing still to a centroid tracker.
        if dist < self.DIST_FIGHT * 2.0:   # within ~2 body-widths
            chaos_a = self._chaos_score(a, 2.0)
            chaos_b = self._chaos_score(b, 2.0)
            # Only allow block if chaos is truly near-zero (genuine conversation)
            if max(chaos_a, chaos_b) >= 0.08:
                return False   # chaotic motion at close range → never block

        v_max = max(va, vb)
        v_sum = va + vb

        # Both very slow AND not in close contact — casual interaction
        if v_max < self.VEL_WALK * 0.5 and v_sum < self.VEL_WALK * 0.8 and dist > self.DIST_FIGHT * 2.0:
            return True

        # Moving in the same direction (walking together, not fighting)
        if self._same_direction(a, b) and v_max < self.VEL_RUN * 0.7 and dist > self.DIST_FIGHT * 1.5:
            return True

        # Separating (closing_speed < 0 means distance is growing)
        if ix.closing_speed < -8.0 and dist > self.DIST_FIGHT * 1.8:
            return True

        # Very stable motion (low chaos on both) AND not close → orderly movement
        chaos_a = self._chaos_score(a, 2.0)
        chaos_b = self._chaos_score(b, 2.0)
        if max(chaos_a, chaos_b) < 0.12 and v_max < self.VEL_RUN * 0.5 and dist > self.DIST_FIGHT * 2.0:
            return True

        return False

    # ── Entry-line crossing detector ─────────────────────────────────────────
    def _entry_crossing(self, active: list, now: float) -> int:
        """
        Count persons whose centroid crosses the horizontal entry_line_y within
        the last 0.5 s.  Used for footfall analytics (ANO-030 / BIZ rules).
        Returns the crossing count for this frame (0 in most frames).
        """
        entry_y = getattr(self, "entry_line_y", None)
        if entry_y is None:
            return 0
        crossings = 0
        for t in active:
            if len(t.positions) < 2:
                continue
            recent = [(x, y, ts) for x, y, ts in t.positions if now - ts <= 0.5]
            if len(recent) < 2:
                continue
            y_prev = recent[0][1]
            y_curr = recent[-1][1]
            if (y_prev < entry_y <= y_curr) or (y_curr < entry_y <= y_prev):
                crossings += 1
        return crossings

    # ── MOG2 fallback: pixel-level high-activity alert ───────────────────────────
    def _mog2_activity_alert(self, active: list, now: float, W: int, H: int) -> Optional[dict]:
        """
        MOG2 fallback alert — fires when YOLO is unavailable.
        Covers four fight/threat scenarios without needing YOLO pairs:

          A. Single person fleeing at very high speed
          B. 2+ persons both running simultaneously
          C. High average scene velocity
          D. 2+ persons in close contact with chaotic motion (grappling/wrestling)
             — the most common real-world fight pattern; low centroid velocity
               but high directional chaos.

        Cooldown: 45 s.
        """
        key = "_MOG2_ACTIVITY"
        if now - self.fired.get(key, 0) < 45:
            return None

        n = len(active)
        if n == 0:
            return None

        vels       = [t.smooth_velocity(0.6) for t in active]
        v_max      = max(vels)
        v_avg      = sum(vels) / n
        chaos_vals = [self._chaos_score(t, 2.0) for t in active]
        chaos_max  = max(chaos_vals)

        # Scenario A: single person fleeing at very high speed
        single_flee = v_max >= self.VEL_FLEE

        # Scenario B: 2+ persons both running simultaneously
        fast_count = sum(1 for v in vels if v >= self.VEL_RUN)
        group_run  = (fast_count >= 2 and v_avg >= self.VEL_WALK * 1.5)

        # Scenario C: elevated scene velocity (lowered threshold — any brisk activity)
        scene_high = (v_avg >= self.VEL_WALK * 1.2 and n >= 1)

        # Scenario D: grappling / wrestling — close proximity + chaotic motion.
        # Two people pressed together barely move their centroids but change
        # direction constantly. Speed-only rules miss this entirely.
        prox_fight = False
        fight_pair_info = ""
        if n >= 2 and chaos_max >= 0.08:
            for i, ta in enumerate(active):
                for tb in active[i+1:]:
                    ax, ay = ta.last_pos()
                    bx, by = tb.last_pos()
                    d = math.hypot(ax - bx, ay - by)
                    ca = self._chaos_score(ta, 2.0)
                    cb = self._chaos_score(tb, 2.0)
                    # Within 3 body-widths AND at least one is chaotic
                    if d < self.DIST_FIGHT * 3.5 and max(ca, cb) >= 0.08:
                        prox_fight = True
                        fight_pair_info = (f"d={int(d)}px "
                                           f"chaos={max(ca,cb):.2f} "
                                           f"v={int(max(ta.smooth_velocity(0.6), tb.smooth_velocity(0.6)))}px/s")
                        break
                if prox_fight:
                    break

        triggered = single_flee or group_run or scene_high or prox_fight

        if not triggered:
            self._tgate_reset(self.scene_triggers, key)
            return None

        # Temporal gate — condition must hold for TW["_MOG2_ACTIVITY"] = 2s
        if not self._tgate(self.scene_triggers, key, now, gap_tol=0.6):
            return None

        # Pick the most descriptive scenario for the alert message
        if prox_fight and not (single_flee or group_run):
            sev  = "HIGH"
            name = "Physical Altercation Suspected"
            desc = f"Two persons in close contact with erratic motion. {fight_pair_info}"
            rate_sev = "HIGH"
        elif single_flee:
            sev  = "HIGH"
            name = "High-Speed Movement / Possible Fleeing"
            desc = f"Person moving at {int(v_max)}px/s — possible fleeing after incident."
            rate_sev = "HIGH"
        elif group_run:
            sev  = "HIGH"
            name = "Group Running / Possible Pursuit"
            desc = f"{fast_count} persons running simultaneously (avg {int(v_avg)}px/s)."
            rate_sev = "HIGH"
        else:
            sev  = "MEDIUM"
            name = "Elevated Scene Activity"
            desc = f"Sustained high activity — {n} persons, avg {int(v_avg)}px/s, chaos={chaos_max:.2f}."
            rate_sev = "MEDIUM"

        if not self._rate_ok(rate_sev, now):
            return None

        self.fired[key] = now
        score = max(35, min(85, int(max(v_avg / self.VEL_RUN, chaos_max * 2) * 70)))

        return _evt(
            "MOG2-ACT", name, "SECURITY", sev, score,
            "SCENE", self.cam_id, self.cam_name, self.zone,
            desc,
            f"v_max={int(v_max)}px/s avg={int(v_avg)}px/s chaos={chaos_max:.2f} n={n}",
            "Review footage immediately. Deploy security if needed.",
            ["motion", "activity", "altercation", "mog2-fallback"],
        )

    # ── Single-person violence detector ──────────────────────────────────────────
    def _single_person_violence_alert(self, active: list, now: float) -> Optional[dict]:
        """
        Detects violent behaviour from a SINGLE tracked person — covers cases
        where only one combatant is visible in frame (e.g. one person being
        filmed mid-fight, attacker in foreground).

        Fires "Fight / Physical Violence Detected" (CRITICAL) when any mature
        track shows the combined fingerprint of a fighter:
          • High directional chaos  (erratic body movement — striking / wrestling)
          • Motion burst count ≥ 2  (repeated velocity spikes — punches / kicks)
          • Minimum speed          (person is not just trembling on the spot)

        Two thresholds:
          STRONG — chaos ≥ 0.45 AND bursts ≥ 2 AND speed ≥ VEL_WALK*0.5
          MODERATE — chaos ≥ 0.30 AND bursts ≥ 3 AND speed ≥ VEL_WALK*0.8

        Cooldown: 30 s per track uid.
        """
        best = None
        best_score = 0.0

        # Diagnostic — shows every frame so we can verify detection pipeline
        mature_count = sum(1 for t in active if len(t.positions) >= 3)
        if self.frame_n % 15 == 1:
            print(f"[SPVA] check: active={len(active)} mature={mature_count} "
                  f"frame={self.frame_n}", flush=True)

        for t in active:
            if len(t.positions) < 3:
                continue
            vel    = t.smooth_velocity(0.5)
            chaos  = self._chaos_score(t, 2.0)
            bursts = self._motion_burst_count(t, 2.0)

            print(f"[SPVA] uid={t.uid} pos={len(t.positions)} "
                  f"chaos={chaos:.3f} bursts={bursts} vel={int(vel)} "
                  f"VEL_WALK={self.VEL_WALK}", flush=True)

            # STRONG: clear fighting signature — very low thresholds
            strong   = (chaos >= 0.18 and bursts >= 1
                        and vel >= self.VEL_WALK * 0.15)
            # MODERATE: grappling / slow wrestling
            moderate = (chaos >= 0.12 and bursts >= 2
                        and vel >= self.VEL_WALK * 0.20)
            # ANY motion burst with minimal chaos — catches sucker punches
            quick    = (bursts >= 3 and vel >= self.VEL_WALK * 0.25)

            if not (strong or moderate or quick):
                continue

            key = f"_SPVA:{t.uid}"
            if now - self.fired.get(key, 0) < 25:
                continue

            composite = (0.45 * min(1.0, chaos / 0.35)
                         + 0.35 * min(1.0, bursts / 2.0)
                         + 0.20 * min(1.0, vel / max(1, self.VEL_RUN)))

            if composite > best_score:
                best_score = composite
                best = (t, key, chaos, bursts, vel, composite)

        if best is None:
            return None

        t, key, chaos, bursts, vel, composite = best

        if not self._rate_ok("CRITICAL", now):
            print(f"[SPVA] RATE_BLOCKED uid={t.uid} chaos={chaos:.2f} bursts={bursts}", flush=True)
            return None

        self.fired[key] = now
        conf = max(65, min(97, int(composite * 100)))

        print(f"[SPVA] FIRED uid={t.uid} chaos={chaos:.2f} bursts={bursts} "
              f"vel={int(vel)} composite={composite:.3f} conf={conf}%", flush=True)

        return _evt(
            "CRM-FIGHT", "Fight / Physical Violence Detected",
            "CRIME", "CRITICAL", conf,
            t.uid, self.cam_id, self.cam_name, self.zone,
            (f"Person {t.uid} showing violent motion signature: "
             f"chaos={chaos:.2f}, bursts={bursts}, vel={int(vel)}px/s. "
             f"Likely engaged in physical altercation."),
            f"chaos={chaos:.2f} burst={bursts} vel={int(vel)}px/s composite={composite:.3f}",
            "Respond immediately. Deploy security. Call police if assault confirmed.",
            ["fight", "violence", "assault", "physical-altercation"],
        )

    # ── Suspicious assault / aggressive behaviour detector ──────────────────────
    def _suspicious_assault_alert(self, active: list, now: float) -> Optional[dict]:
        """
        Fires HIGH alert 'Suspicious Aggressive Behaviour' when any tracked
        person shows suspicious physical activity that may indicate an assault
        in progress or about to begin:
          • Sudden acceleration spike (velocity jumped > VEL_WALK in <0.5s)
          • High chaos without requiring motion bursts (aggressive flailing)
          • Rapid approach toward another person combined with high velocity
        Fires CRM-SUSP (HIGH, confidence 65–88). Cooldown 20 s per track.
        Lower bar than CRM-FIGHT — catches suspicious activity early.
        """
        for t in active:
            if len(t.positions) < 3:
                continue

            vel    = t.smooth_velocity(0.5)
            chaos  = self._chaos_score(t, 1.5)
            bursts = self._motion_burst_count(t, 2.0)

            # Rapid approach toward another person
            rapid_approach = False
            if len(active) >= 2 and vel >= self.VEL_WALK * 0.8:
                tx, ty = t.last_pos()
                for other in active:
                    if other.uid == t.uid: continue
                    ox, oy = other.last_pos()
                    dist = math.hypot(tx - ox, ty - oy)
                    if dist < self.DIST_SNATCH * 2.2:
                        rapid_approach = True
                        break

            # Sudden acceleration — compare old half vs new half of position window
            sudden_accel = False
            if len(t.positions) >= 8:
                pts = list(t.positions)[-8:]
                def _seg_vel(seg):
                    dists, dts = [], []
                    for i in range(1, len(seg)):
                        x1,y1,t1=seg[i-1]; x2,y2,t2=seg[i]
                        dt=max(t2-t1,0.001)
                        dists.append(math.hypot(x2-x1,y2-y1))
                        dts.append(dt)
                    return sum(dists)/max(sum(dts),0.001)
                old_v = _seg_vel(pts[:4])
                new_v = _seg_vel(pts[4:])
                if new_v > old_v * 2.0 and new_v >= self.VEL_WALK * 0.6:
                    sudden_accel = True

            # High chaos alone (aggressive gesturing / flailing)
            high_chaos = (chaos >= 0.35 and vel >= self.VEL_WALK * 0.2)

            triggered = rapid_approach or sudden_accel or high_chaos

            if not triggered:
                continue

            key = f"_SUSP:{t.uid}"
            if now - self.fired.get(key, 0) < 20:
                continue

            if not self._rate_ok("HIGH", now):
                continue

            self.fired[key] = now

            reason = ("rapid approach" if rapid_approach
                      else "sudden acceleration" if sudden_accel
                      else "aggressive motion")
            composite = (0.4 * min(1.0, chaos / 0.5)
                         + 0.3 * min(1.0, vel / max(1, self.VEL_RUN))
                         + 0.3 * min(1.0, bursts / 3.0))
            conf = max(65, min(88, int(composite * 100) + 30))

            print(f"[SUSP] FIRED uid={t.uid} reason={reason} chaos={chaos:.2f} "
                  f"vel={int(vel)} conf={conf}%", flush=True)

            return _evt(
                "CRM-SUSP", "Suspicious Aggressive Behaviour",
                "CRIME", "HIGH", conf,
                t.uid, self.cam_id, self.cam_name, self.zone,
                (f"Person {t.uid} displaying suspicious aggressive behaviour "
                 f"({reason}): chaos={chaos:.2f}, vel={int(vel)}px/s, bursts={bursts}. "
                 f"Possible assault or confrontation developing."),
                f"reason={reason} chaos={chaos:.2f} vel={int(vel)}px/s",
                "Monitor closely. Position security personnel. Be ready to intervene.",
                ["suspicious", "aggressive", "assault-precursor", "threatening"],
            )
        return None

    # ── Is this track currently in proximity with ANY other track? ────────────────
    def _in_any_interaction(self, t: PersonTrack, now: float) -> bool:
        others = [tr for tr in self.tracks.values()
                  if tr.uid != t.uid and now - tr.last_seen < 2.0]
        for other in others:
            pk = f"{min(t.uid, other.uid)}:{max(t.uid, other.uid)}"
            ts = self._interaction_start.get(pk)
            if ts is not None and (now - ts) >= 0.5:
                ax, ay = t.last_pos()
                bx, by = other.last_pos()
                if math.hypot(ax - bx, ay - by) < getattr(self, "DIST_SNATCH", 110) * 1.6:
                    return True
        return False

    # ── Rule priority filter: CRIME > SECURITY > ANOMALY > BEHAVIOR ───────────────
    # Applied once per frame after all rules run.
    # Prevents lower-priority alerts from drowning out real crime detections.
    @staticmethod
    def _apply_priority_filter(events: List[dict]) -> List[dict]:
        """
        Priority hierarchy: CRIME > PRE-ALERT > SECURITY > ANOMALY > BEHAVIOR

        Confirmed CRIME (non-pre_alert) overrides EVERYTHING including pre-alerts.
        Pre-alert (PA-001) overrides SECURITY/BEHAVIOR/ANOMALY only.
        Pre-alerts are NEVER shown alongside a confirmed CRIME — one or the other.
        """
        if not events:
            return events

        # Partition events
        confirmed_crimes = [e for e in events
                            if e.get("category") == "CRIME"
                            and not e.get("pre_alert", False)]
        pre_alerts       = [e for e in events if e.get("pre_alert", False)]
        crowd_emergency  = [e for e in events if e.get("category") == "CROWD"]
        critical_sec     = [e for e in events
                            if e.get("category") == "SECURITY"
                            and e.get("severity") == "CRITICAL"]
        other_events     = [e for e in events
                            if e not in confirmed_crimes
                            and e not in pre_alerts
                            and e not in crowd_emergency
                            and e not in critical_sec]

        # Confirmed CRIME present → suppress everything except CRIME + CROWD + CRITICAL SEC
        if confirmed_crimes:
            return confirmed_crimes + crowd_emergency + critical_sec

        # Pre-alerts present (no confirmed CRIME) → show pre-alerts + CROWD + CRITICAL SEC
        # Suppress regular SECURITY, BEHAVIOR, ANOMALY to avoid noise alongside PA-001
        cats = {e.get("category", "") for e in events}
        if pre_alerts:
            return pre_alerts + crowd_emergency + critical_sec

        # No CRIME or pre-alert — apply standard priority suppression
        if "SECURITY" in cats:
            return [e for e in events
                    if e.get("category") != "BEHAVIOR"
                    or e.get("severity") == "CRITICAL"]

        return events

    # ── Adaptive load control ─────────────────────────────────────────────────
    def _update_load_control(self):
        """
        Auto-tune _skip_n based on measured per-frame processing time.

        _skip_n = 1 : process every frame   (normal)
        _skip_n = 2 : process every 2nd frame (light load shedding)
        _skip_n = 4 : process every 4th frame (heavy load shedding)

        Thresholds (milliseconds per frame):
          > 150 ms → raise skip   (too slow, approaching 6 fps)
          < 60 ms  → lower skip   (fast enough, recover quality)
        """
        if len(self._proc_times) < 10:
            return
        avg_ms = sum(self._proc_times) / len(self._proc_times) * 1000.0
        if avg_ms > 150 and self._skip_n < 4:
            self._skip_n += 1
        elif avg_ms < 60 and self._skip_n > 1:
            self._skip_n = max(1, self._skip_n - 1)

    # ── ANO rules ─────────────────────────────────────────────────────────────
    def _anomaly_rules(self, active, count, W, H, now,
                       gray: np.ndarray, events_so_far: int) -> List[dict]:
        events: List[dict] = []
        brightness = float(np.mean(gray))

        # Update count history (120s window)
        self._count_history.append((now, count))
        self._count_history = [(t, c) for t, c in self._count_history if now - t <= 120.0]

        # Update hourly velocity baseline
        hour = int(time.strftime("%H"))
        if active:
            scene_vel = sum(t.smooth_velocity(0.6) for t in active) / len(active)
        else:
            scene_vel = 0.0
        self._vel_baseline[hour].append(scene_vel)
        if len(self._vel_baseline[hour]) > 300:
            self._vel_baseline[hour] = self._vel_baseline[hour][-300:]

        # ANO-034: Blank / near-dark frame
        if brightness < 8.0:
            if self._tgate(self.scene_triggers, "ANO-034", now, gap_tol=0.5):
                ev = self._fire2("ANO-034", 75, now,
                    "ANOMALY","HIGH","Blank Frame / Feed Interruption",
                    "Camera feed appears dark or blank — possible tamper or power failure.",
                    f"Mean brightness={brightness:.1f} < 8",
                    "Check camera power and connection. Inspect for tampering.",
                    ["blank-frame","dark-feed","tamper"])
                if ev: events.append(ev)
        else:
            self._tgate_reset(self.scene_triggers, "ANO-034")

        # ANO-009: Sudden illumination change
        if self._prev_brightness is not None:
            change = abs(brightness - self._prev_brightness) / max(self._prev_brightness, 1.0)
            if change > 0.35:
                if self._tgate(self.scene_triggers, "ANO-009", now, gap_tol=0.3):
                    ev = self._fire2("ANO-009", 55, now,
                        "ANOMALY","MEDIUM","Sudden Illumination Change",
                        "Scene brightness changed abruptly — possible lighting manipulation.",
                        f"Brightness {self._prev_brightness:.0f}→{brightness:.0f} (Δ{change*100:.0f}%)",
                        "Check lighting system. Inspect for cover-ups.",
                        ["illumination","lighting-change","tampering"])
                    if ev: events.append(ev)
            else:
                self._tgate_reset(self.scene_triggers, "ANO-009")
        self._prev_brightness = brightness

        # ANO-001: Unexpected crowd thinning (>45% drop vs 60s ago)
        old = [c for t, c in self._count_history if now - t >= 55.0]
        if old:
            old_avg = sum(old) / len(old)
            if old_avg >= 3 and count < old_avg * 0.55:
                if self._tgate(self.scene_triggers, "ANO-001", now, gap_tol=2.0):
                    ev = self._fire2("ANO-001", 72, now,
                        "ANOMALY","HIGH","Unexpected Crowd Thinning",
                        "Rapid occupancy drop — possible silent evacuation or threat.",
                        f"Occupancy {int(old_avg)}→{count} ({int((1-count/max(old_avg,1))*100)}% drop)",
                        "Alert security. Check for unreported threat. Staff sweep.",
                        ["crowd-thinning","silent-evacuation","anomaly"])
                    if ev: events.append(ev)
            else:
                self._tgate_reset(self.scene_triggers, "ANO-001")

        # ANO-004: Velocity distribution anomaly (>2.5× hourly baseline)
        baseline_pts = self._vel_baseline[hour][:-10] if len(self._vel_baseline[hour]) > 20 else []
        if baseline_pts and active:
            baseline_avg = sum(baseline_pts) / len(baseline_pts)
            if baseline_avg > 0 and scene_vel > baseline_avg * 2.5 and count > 2:
                if self._tgate(self.scene_triggers, "ANO-004", now, gap_tol=1.0):
                    ev = self._fire2("ANO-004", 48, now,
                        "ANOMALY","MEDIUM","Velocity Distribution Anomaly",
                        "Scene average velocity significantly above normal baseline.",
                        f"scene_vel={int(scene_vel)}px/s > 2.5×baseline={int(baseline_avg)}px/s",
                        "Review scene. Dispatch security.",
                        ["velocity-anomaly","baseline-deviation","statistical"])
                    if ev: events.append(ev)
            else:
                self._tgate_reset(self.scene_triggers, "ANO-004")

        # ANO-027a: Scene-wide motion freeze (all persons stationary, count ≥ 4)
        if count >= 4:
            mobile = [t for t in active if t.is_mobile()]
            if len(mobile) == 0:
                if self._tgate(self.scene_triggers, "ANO-027a", now, gap_tol=2.0):
                    ev = self._fire2("ANO-027a", 62, now,
                        "ANOMALY","HIGH","Scene-Wide Motion Freeze",
                        "All persons suddenly stationary — possible armed threat causing freeze response.",
                        f"{count} persons all stationary simultaneously",
                        "Alert security immediately. Possible armed threat or confrontation.",
                        ["scene-freeze","threat-response","anomaly"])
                    if ev: events.append(ev)
            else:
                self._tgate_reset(self.scene_triggers, "ANO-027a")

        # ANO-019: Multiple simultaneous incidents
        if events_so_far >= 3:
            if self._tgate(self.scene_triggers, "ANO-019", now, gap_tol=5.0):
                ev = self._fire2("ANO-019", 80, now,
                    "ANOMALY","CRITICAL","Multiple Simultaneous Incidents",
                    "3+ rule triggers in a single frame — coordinated attack or major incident.",
                    f"{events_so_far} simultaneous alerts fired",
                    "Alert all security. Consider lockdown protocol.",
                    ["multiple-incidents","coordinated","critical-event"])
                if ev: events.append(ev)
        else:
            self._tgate_reset(self.scene_triggers, "ANO-019")

        # ANO-035: High alert rate (>15 alerts/60s)
        self._alert_history.append(now)
        self._alert_history = [t for t in self._alert_history if now - t <= 60.0]
        if len(self._alert_history) > 15:
            if self._tgate(self.scene_triggers, "ANO-035", now, gap_tol=5.0):
                ev = self._fire2("ANO-035", 35, now,
                    "ANOMALY","MEDIUM","High Alert Rate — Calibration Needed",
                    f"{len(self._alert_history)} alerts in 60s — possible false positive surge.",
                    f"{len(self._alert_history)} alerts/60s > threshold 15",
                    "Review system calibration. Check for false positive sources.",
                    ["high-alert-rate","calibration","system-health"])
                if ev: events.append(ev)

        return events

    # ── SYS rules ─────────────────────────────────────────────────────────────
    def _sys_rules(self, now: float, gray: np.ndarray) -> List[dict]:
        events: List[dict] = []
        self._fps_frame_count += 1

        # SYS-002: Image blur — per frame, debounced by tgate
        lap_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        if lap_var < 20.0:
            if self._tgate(self.scene_triggers, "SYS-002", now, gap_tol=2.0):
                key = "SYS-002"
                if now - self.fired.get(key, 0) > self.CD.get(key, 120):
                    self.fired[key] = now
                    events.append(_evt(key, "Camera Image Quality Degraded",
                        "SYSTEM","MEDIUM", 50, "SYSTEM",
                        self.cam_id, self.cam_name, self.zone,
                        f"Image blur detected (Laplacian var={lap_var:.1f} < 20).",
                        f"lap_var={lap_var:.1f}<20 sustained 5s",
                        "Check camera lens. Clean or adjust focus.",
                        ["blur","image-quality","system-health"]))
        else:
            self._tgate_reset(self.scene_triggers, "SYS-002")

        # Remaining SYS checks: throttled to once per 30s
        if now - self._last_sys_check < 30.0:
            return events
        self._last_sys_check = now

        # SYS-003: FPS drop
        elapsed = now - self._fps_window_start
        if elapsed >= 10.0:
            actual_fps = self._fps_frame_count / elapsed
            self._fps_window_start = now
            self._fps_frame_count  = 0
            if actual_fps < 3.0:
                key = "SYS-003"
                if now - self.fired.get(key, 0) > self.CD.get(key, 120):
                    self.fired[key] = now
                    events.append(_evt(key, "Frame Rate Drop Detected",
                        "SYSTEM","MEDIUM", 55, "SYSTEM",
                        self.cam_id, self.cam_name, self.zone,
                        f"Actual FPS dropped to {actual_fps:.1f} (expected ≥5).",
                        f"actual_fps={actual_fps:.1f} < 3",
                        "Check system resources. Reduce camera count or resolution.",
                        ["fps-drop","performance","system-health"]))

        # SYS-005: CPU / Memory (requires psutil)
        try:
            import psutil as _psutil
            cpu = _psutil.cpu_percent(interval=None)
            mem = _psutil.virtual_memory().percent
            if cpu > 90 or mem > 90:
                key = "SYS-005"
                if now - self.fired.get(key, 0) > self.CD.get(key, 300):
                    self.fired[key] = now
                    events.append(_evt(key, "High CPU / Memory Usage",
                        "SYSTEM","HIGH", 70, "SYSTEM",
                        self.cam_id, self.cam_name, self.zone,
                        f"System resources critical: CPU={cpu:.0f}% MEM={mem:.0f}%.",
                        f"cpu={cpu:.0f}%>90 OR mem={mem:.0f}%>90",
                        "Reduce load. Stop unused cameras. Check runaway processes.",
                        ["cpu","memory","system-health"]))
        except ImportError:
            pass

        # SYS-006: Disk storage
        try:
            import shutil as _shutil_sys
            total, used, _ = _shutil_sys.disk_usage("/")
            pct = used / total * 100
            if pct > 90:
                key = "SYS-006"
                if now - self.fired.get(key, 0) > self.CD.get(key, 600):
                    self.fired[key] = now
                    events.append(_evt(key, "Disk Storage Warning",
                        "SYSTEM","HIGH", 65, "SYSTEM",
                        self.cam_id, self.cam_name, self.zone,
                        f"Disk usage critical: {pct:.0f}% used.",
                        f"disk_used={pct:.0f}%>90",
                        "Delete old recordings. Archive to external storage.",
                        ["disk","storage","system-health"]))
        except Exception:
            pass

        return events

    def _draw(self, frame, active, blobs, W, H, events):
        out = frame.copy()
        # Entry line
        cv2.line(out, (0, self.entry_y), (W, self.entry_y), (0,180,255), 1)
        # Restricted zone
        x1f,y1f,x2f,y2f = self.restricted_zone
        rx1,ry1,rx2,ry2 = int(x1f*W),int(y1f*H),int(x2f*W),int(y2f*H)
        ovl = out.copy()
        cv2.rectangle(ovl,(rx1,ry1),(rx2,ry2),(0,0,180),-1)
        cv2.addWeighted(ovl,0.10,out,0.90,0,out)
        cv2.rectangle(out,(rx1,ry1),(rx2,ry2),(0,0,200),1)

        STATE_COLOR = {
            HumanState.IDLE:     (100,100,100),
            HumanState.STANDING: (0,200,100),
            HumanState.SITTING:  (0,200,200),
            HumanState.WALKING:  (0,180,255),
            HumanState.RUNNING:  (0,100,255),
            HumanState.FLEEING:  (0,0,255),
            HumanState.FALLEN:   (0,50,200),
        }

        for t in active:
            if not t.bboxes: continue
            x,y,bw,bh = t.bboxes[-1]
            col = STATE_COLOR.get(t.state, (100,100,100))
            cv2.rectangle(out,(x,y),(x+bw,y+bh),col,2)
            vel = t.smooth_velocity(0.6)
            label = f"{t.state.value[:3]} {int(vel)}px/s"
            cv2.putText(out, label, (x, max(y-3,10)),
                        cv2.FONT_HERSHEY_PLAIN, 0.65, col, 1)

        # Alert flash border
        crit = any(e["severity"]=="CRITICAL" for e in events)
        if crit:
            cv2.rectangle(out,(0,0),(W,H),(0,0,255),5)
            cv2.putText(out,"! ALERT !",(W//2-55, H//2),
                        cv2.FONT_HERSHEY_DUPLEX,1.5,(0,0,255),2)

        # HUD bar
        warmup = f" WARMUP:{max(0,self.WARMUP_FRAMES-self.frame_n)}" \
                 if self.frame_n < self.WARMUP_FRAMES else ""
        cv2.rectangle(out,(0,0),(W,16),(0,0,0),-1)
        cv2.putText(out,
            f"{self.cam_id} | {self.zone} | {time.strftime('%H:%M:%S')} | P:{len(active)}{warmup}",
            (3,11), cv2.FONT_HERSHEY_PLAIN, 0.65, (200,200,200), 1)
        return out


# ─── Shared helpers ────────────────────────────────────────────────────────────
def _evt(rule_id, name, category, severity, score, person_id,
         cam_id, cam_name, zone, desc, trigger, action, reasons):
    return {
        "type":        "ALERT",
        "event_id":    f"EVT-{int(time.time()*1000)%100000000}",
        "rule_id":     rule_id,
        "rule_name":   name,
        "category":    category,
        "severity":    severity,
        "risk_score":  score,
        "person_id":   person_id,
        "camera_id":   cam_id,
        "camera_name": cam_name,
        "zone":        zone,
        "description": desc,
        "trigger":     trigger,
        "action":      action,
        "reasons":     reasons,
        "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%S"),
    }

def _nms(boxes, thresh):
    if not boxes: return []
    arr = np.array([[x,y,x+w,y+h] for x,y,w,h in boxes], dtype=float)
    x1,y1,x2,y2 = arr[:,0],arr[:,1],arr[:,2],arr[:,3]
    areas = (x2-x1)*(y2-y1)
    order = areas.argsort()[::-1]
    keep  = []
    while order.size:
        i = order[0]; keep.append(i)
        xx1=np.maximum(x1[i],x1[order[1:]]); yy1=np.maximum(y1[i],y1[order[1:]])
        xx2=np.minimum(x2[i],x2[order[1:]]); yy2=np.minimum(y2[i],y2[order[1:]])
        w=np.maximum(0.,xx2-xx1); h=np.maximum(0.,yy2-yy1)
        iou=(w*h)/(areas[i]+areas[order[1:]]-w*h)
        order=order[np.where(iou<=thresh)[0]+1]
    ox=arr[keep,0]; oy=arr[keep,1]
    return [(int(ox[k]),int(oy[k]),
             int(arr[keep[k],2]-ox[k]),int(arr[keep[k],3]-oy[k]))
            for k in range(len(keep))]

def _cluster_spread(positions):
    if len(positions) < 2: return 9999.
    xs,ys = zip(*positions)
    return max(max(xs)-min(xs), max(ys)-min(ys))
