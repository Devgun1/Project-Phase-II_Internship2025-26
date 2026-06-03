"""
Raksha Vision Core — Telegram Alert Notifier
=============================================
Sends validated security alerts to a Telegram group/channel via Bot API.

Configuration (environment variables — override defaults below):
  TELEGRAM_BOT_TOKEN   Bot token from @BotFather
  TELEGRAM_CHAT_ID     Group/channel ID (negative for groups, e.g. -1003852125408)

Behaviour:
  • Only dispatches alerts with confidence_score >= TELEGRAM_MIN_CONFIDENCE (85)
  • Per-rule cooldown of TELEGRAM_COOLDOWN_SEC (120 s) prevents spam
  • All HTTP calls run in daemon threads — never blocks the asyncio event loop
  • Telegram API failures are logged and silently swallowed (never crash the server)
  • Supports text messages, photo snapshots, and short video clips
"""

import logging
import os
import threading
import time
from datetime import datetime
from typing import Optional

log = logging.getLogger("raksha.telegram")

# ── Configuration ─────────────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = os.environ.get(
    "TELEGRAM_BOT_TOKEN", "8888499917:AAEEY0tmx9lMmgP3zA61MOZjeppe1Ar9zKM")
TELEGRAM_CHAT_ID = os.environ.get(
    "TELEGRAM_CHAT_ID", "-1003852125408")

# Per-severity minimum confidence thresholds (0–100 scale)
# CRITICAL events (fights, assaults) are sent at lower confidence — missing a
# real fight is worse than an occasional false positive.
_TELEGRAM_MIN_CONF: dict[str, int] = {
    "CRITICAL": int(os.environ.get("TELEGRAM_MIN_CONF_CRITICAL", "60")),
    "HIGH":     int(os.environ.get("TELEGRAM_MIN_CONF_HIGH",     "60")),
    "MEDIUM":   int(os.environ.get("TELEGRAM_MIN_CONF_MEDIUM",   "999")),  # disabled
    "LOW":      int(os.environ.get("TELEGRAM_MIN_CONF_LOW",      "999")),  # disabled
}
# Backward-compat env var — if set it overrides all levels
_TELEGRAM_GLOBAL_MIN = os.environ.get("TELEGRAM_MIN_CONFIDENCE", "")

# Seconds before the same rule can trigger another Telegram message
TELEGRAM_COOLDOWN_SEC: int = int(os.environ.get("TELEGRAM_COOLDOWN_SEC", "60"))

# Base API URL — built once at import time
_API_BASE = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

# ── Internal cooldown tracker ─────────────────────────────────────────────────
_last_sent: dict[str, float] = {}
_lock = threading.Lock()

# ── Severity → emoji ──────────────────────────────────────────────────────────
_SEV_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def dispatch(alert: dict) -> None:
    """
    Primary entry point — call with a validated alert dict.

    Checks confidence threshold and per-rule cooldown, then dispatches
    the alert (with snapshot photo if available) in a daemon thread.
    Does nothing if the token or chat ID is not configured.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return

    # ── Confidence gate — severity-aware ─────────────────────────────────────
    # Field is "risk_score" in _evt() — also check legacy names
    conf = (alert.get("risk_score")
            or alert.get("confidence_score")
            or alert.get("score")
            or 0)
    try:
        conf = int(conf)
    except (TypeError, ValueError):
        conf = 0

    sev = alert.get("severity", "HIGH").upper()
    if _TELEGRAM_GLOBAL_MIN:
        min_conf = int(_TELEGRAM_GLOBAL_MIN)
    else:
        min_conf = _TELEGRAM_MIN_CONF.get(sev, 999)

    if conf < min_conf:
        log.debug(f"[telegram] skipped {alert.get('rule_id')} — conf {conf} < {min_conf} for {sev}")
        print(f"[TELEGRAM] SKIPPED {alert.get('rule_id')} conf={conf} min={min_conf} sev={sev}", flush=True)
        return

    # ── Per-rule cooldown ─────────────────────────────────────────────────────
    rule_key = alert.get("rule_id") or alert.get("event_id") or "unknown"
    with _lock:
        if time.time() - _last_sent.get(rule_key, 0) < TELEGRAM_COOLDOWN_SEC:
            log.debug(f"[telegram] skipped {rule_key} — cooldown active")
            return
        _last_sent[rule_key] = time.time()

    # ── Dispatch in background thread ─────────────────────────────────────────
    print(f"[TELEGRAM] SENDING {alert.get('rule_id')} sev={sev} conf={conf}% → {TELEGRAM_CHAT_ID}", flush=True)
    threading.Thread(
        target=_dispatch_sync, args=(alert, conf), daemon=True
    ).start()


def send_message(text: str, parse_mode: str = "Markdown") -> bool:
    """
    Send a plain text message to the configured chat.
    Returns True on success, False on failure.
    """
    try:
        import requests
        resp = requests.post(
            f"{_API_BASE}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID,
                  "text": text,
                  "parse_mode": parse_mode},
            timeout=10,
        )
        resp.raise_for_status()
        return True
    except Exception as exc:
        log.error(f"[telegram] sendMessage failed: {exc}")
        return False


def send_photo(photo_path: str, caption: str = "",
               parse_mode: str = "Markdown") -> bool:
    """
    Send a JPEG/PNG snapshot to the configured chat.
    Returns True on success, False on failure.
    """
    if not os.path.isfile(photo_path):
        log.warning(f"[telegram] send_photo: file not found: {photo_path}")
        return False
    try:
        import requests
        with open(photo_path, "rb") as f:
            resp = requests.post(
                f"{_API_BASE}/sendPhoto",
                data={"chat_id":    TELEGRAM_CHAT_ID,
                      "caption":    caption[:1024],   # Telegram limit
                      "parse_mode": parse_mode},
                files={"photo": f},
                timeout=20,
            )
        resp.raise_for_status()
        return True
    except Exception as exc:
        log.error(f"[telegram] sendPhoto failed: {exc}")
        return False


def send_video(video_path: str, caption: str = "",
               parse_mode: str = "Markdown") -> bool:
    """
    Send a short video clip to the configured chat.
    Telegram limit: 50 MB. Returns True on success, False on failure.
    """
    if not os.path.isfile(video_path):
        log.warning(f"[telegram] send_video: file not found: {video_path}")
        return False
    try:
        import requests
        with open(video_path, "rb") as f:
            resp = requests.post(
                f"{_API_BASE}/sendVideo",
                data={"chat_id":    TELEGRAM_CHAT_ID,
                      "caption":    caption[:1024],
                      "parse_mode": parse_mode},
                files={"video": f},
                timeout=60,
            )
        resp.raise_for_status()
        return True
    except Exception as exc:
        log.error(f"[telegram] sendVideo failed: {exc}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _build_message(alert: dict, conf: int) -> str:
    """Build a formatted Telegram alert message from an alert dict."""
    sev    = alert.get("severity", "HIGH").upper()
    emoji  = _SEV_EMOJI.get(sev, "⚠️")
    name   = alert.get("rule_name") or alert.get("name", "Unknown Alert")
    cam    = alert.get("camera_name") or alert.get("camera_id", "Unknown Camera")
    zone   = alert.get("zone", "")
    desc   = alert.get("description", "")
    action = alert.get("action", "")
    rule   = alert.get("rule_id", "")
    # risk_score is the canonical field name in _evt()
    conf   = int(alert.get("risk_score") or alert.get("confidence_score") or conf)
    ts_raw = alert.get("timestamp", "")

    # Format timestamp
    try:
        dt = datetime.fromisoformat(str(ts_raw))
        ts_fmt = dt.strftime("%d %b %Y  %H:%M:%S")
    except Exception:
        ts_fmt = str(ts_raw) if ts_raw else datetime.now().strftime("%d %b %Y  %H:%M:%S")

    zone_line   = f"📍 *Zone:* {zone}\n"   if zone   else ""
    action_line = f"\n⚡ *Action:* {action}" if action else ""

    return (
        f"{emoji} *{sev} ALERT — {name}*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"📷 *Camera:* {cam}\n"
        f"{zone_line}"
        f"🎯 *Confidence:* {conf}%\n"
        f"🕒 *Time:* {ts_fmt}\n"
        f"📝 *Details:* {desc}"
        f"{action_line}\n"
        f"_`{rule}` · Raksha Vision Core_"
    )


def _dispatch_sync(alert: dict, conf: int) -> None:
    """Synchronous dispatch — runs inside a daemon thread."""
    message      = _build_message(alert, conf)
    snapshot     = alert.get("snapshot_path", "")
    video_clip   = alert.get("video_clip_path", "")

    if video_clip and os.path.isfile(video_clip):
        # Video clip takes priority — includes audio/motion evidence
        success = send_video(video_clip, caption=message)
        if success:
            log.info(f"[telegram] video sent for {alert.get('rule_id')}")
            return

    if snapshot and os.path.isfile(snapshot):
        # Photo snapshot — most common case
        success = send_photo(snapshot, caption=message)
        if success:
            log.info(f"[telegram] photo sent for {alert.get('rule_id')}")
            return
        log.warning("[telegram] photo failed — falling back to text")

    # Text-only fallback
    success = send_message(message)
    if success:
        log.info(f"[telegram] text sent for {alert.get('rule_id')}")
    else:
        log.error(f"[telegram] all delivery methods failed for {alert.get('rule_id')}")


def send_startup_notification() -> None:
    """
    Send a startup ping to confirm bot connectivity.
    Called once at server startup — safe to call from a daemon thread.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    now = datetime.now().strftime("%d %b %Y  %H:%M:%S")
    msg = (
        "✅ *Raksha Vision Core — Online*\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"🕒 *Started:* {now}\n"
        "🎯 *Alert delivery:* ACTIVE\n"
        "_Waiting for camera feed…_"
    )
    threading.Thread(target=send_message, args=(msg,), daemon=True).start()
    print("[TELEGRAM] Startup notification sent", flush=True)
