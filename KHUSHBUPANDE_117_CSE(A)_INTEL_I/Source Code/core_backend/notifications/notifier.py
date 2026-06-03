"""
Raksha Vision Core — Notification Dispatcher
=============================================
Fires push notifications (email, webhook, Telegram) on CRITICAL/HIGH alerts.
Runs entirely in background threads — never blocks the asyncio event loop.

Email (SMTP):
  SMTP_HOST        SMTP server hostname (leave empty to disable email)
  SMTP_PORT        port, default 587
  SMTP_USER        login username
  SMTP_PASS        login password
  SMTP_FROM        From address (falls back to SMTP_USER)
  SMTP_TO          comma-separated recipient list
  SMTP_TLS         use STARTTLS, default true

Webhook (HTTP POST with JSON body):
  WEBHOOK_URL      target endpoint (leave empty to disable)
  WEBHOOK_SECRET   optional HMAC-SHA256 signing secret (raw string)

Telegram:
  See core_backend/notifications/telegram_notifier.py
  Env vars: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_MIN_CONFIDENCE,
            TELEGRAM_COOLDOWN_SEC

Tuning:
  NOTIFY_SEVERITIES   comma-separated severity levels to notify, default CRITICAL,HIGH
  NOTIFY_COOLDOWN     seconds between repeat notifications for the same rule, default 300
"""

import hashlib
import hmac
import json
import logging
import os
import smtplib
import threading
import time
import urllib.request
import urllib.error
import urllib.parse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from core_backend.notifications import telegram_notifier as _tg

log = logging.getLogger("raksha.notifier")

# ── Config ───────────────────────────────────────────────────────────────────
NOTIFY_SEVERITIES = {
    s.strip().upper()
    for s in os.environ.get("NOTIFY_SEVERITIES", "CRITICAL,HIGH").split(",")
    if s.strip()
}
NOTIFY_COOLDOWN = int(os.environ.get("NOTIFY_COOLDOWN", "300"))

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "") or SMTP_USER
SMTP_TO   = [r.strip() for r in os.environ.get("SMTP_TO", "").split(",") if r.strip()]
SMTP_TLS  = os.environ.get("SMTP_TLS", "true").lower() not in ("false", "0", "no")

WEBHOOK_URL    = os.environ.get("WEBHOOK_URL", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")

# ── Rate-limit state: rule_id → last notification timestamp ─────────────────
_last_notified: dict = {}
_lock = threading.Lock()


def dispatch(alert: dict):
    """
    Public entry point. Call with a raw alert dict.
    Checks severity + cooldown, then dispatches in a daemon thread.
    """
    severity = alert.get("severity", "").upper()
    if severity not in NOTIFY_SEVERITIES:
        return

    rule_id = alert.get("rule_id") or alert.get("event_id") or "unknown"
    with _lock:
        last = _last_notified.get(rule_id, 0.0)
        if time.time() - last < NOTIFY_COOLDOWN:
            return
        _last_notified[rule_id] = time.time()

    threading.Thread(target=_dispatch_sync, args=(alert,), daemon=True).start()


def _dispatch_sync(alert: dict):
    """Synchronous dispatch executed in a worker thread."""
    if SMTP_HOST and SMTP_TO:
        try:
            _send_email(alert)
        except Exception as exc:
            log.error(f"[notifier] email failed: {exc}")

    if WEBHOOK_URL:
        try:
            _send_webhook(alert)
        except Exception as exc:
            log.error(f"[notifier] webhook failed: {exc}")

    # Telegram — handled by dedicated module (own cooldown + confidence gate)
    _tg.dispatch(alert)


# ── Email ─────────────────────────────────────────────────────────────────────

def _send_email(alert: dict):
    cam    = alert.get("camera_name") or alert.get("camera_id", "unknown")
    sev    = alert.get("severity", "?")
    rule   = f"{alert.get('rule_id', '?')} — {alert.get('rule_name', '?')}"
    ts     = alert.get("timestamp", "")
    desc   = alert.get("description", "")
    action = alert.get("action", "")

    subject = f"[Raksha] {sev} Alert — {alert.get('rule_name', 'Unknown')}"

    plain = (
        "RAKSHA VISION CORE — SECURITY ALERT\n"
        "=" * 44 + "\n"
        f"Severity  : {sev}\n"
        f"Rule      : {rule}\n"
        f"Camera    : {cam}\n"
        f"Time      : {ts}\n"
        f"Details   : {desc}\n"
        f"Action    : {action}\n"
    )

    # Safe HTML — values are inserted as text, not markup
    def _esc(v: str) -> str:
        return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    html = f"""<html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px">
<div style="max-width:600px;margin:auto;background:#fff;border-radius:8px;overflow:hidden">
  <div style="background:#c00;padding:16px;color:#fff">
    <h2 style="margin:0">&#x26A0; Raksha Vision Core &mdash; {_esc(sev)} Alert</h2>
  </div>
  <table style="width:100%;border-collapse:collapse;font-size:14px">
    <tr style="background:#ffeaea"><td style="padding:8px 16px;font-weight:bold">Severity</td>
        <td style="padding:8px 16px">{_esc(sev)}</td></tr>
    <tr><td style="padding:8px 16px;font-weight:bold">Rule</td>
        <td style="padding:8px 16px">{_esc(rule)}</td></tr>
    <tr style="background:#f9f9f9"><td style="padding:8px 16px;font-weight:bold">Camera</td>
        <td style="padding:8px 16px">{_esc(cam)}</td></tr>
    <tr><td style="padding:8px 16px;font-weight:bold">Time</td>
        <td style="padding:8px 16px">{_esc(ts)}</td></tr>
    <tr style="background:#f9f9f9"><td style="padding:8px 16px;font-weight:bold">Description</td>
        <td style="padding:8px 16px">{_esc(desc)}</td></tr>
    <tr><td style="padding:8px 16px;font-weight:bold">Action</td>
        <td style="padding:8px 16px">{_esc(action)}</td></tr>
  </table>
  <div style="padding:12px 16px;font-size:11px;color:#888">Raksha Vision Core &mdash; Automated Security Alert</div>
</div>
</body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_FROM
    msg["To"]      = ", ".join(SMTP_TO)
    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html,  "html",  "utf-8"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
        if SMTP_TLS:
            s.starttls()
        if SMTP_USER and SMTP_PASS:
            s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(SMTP_FROM, SMTP_TO, msg.as_string())

    log.info(f"[notifier] email sent for {alert.get('rule_id')} → {SMTP_TO}")


# ── Webhook ───────────────────────────────────────────────────────────────────

def _send_webhook(alert: dict):
    payload = json.dumps(alert, default=str).encode("utf-8")
    headers: dict = {
        "Content-Type": "application/json",
        "User-Agent":   "RakshaVisionCore/2.0",
    }
    if WEBHOOK_SECRET:
        sig = hmac.new(
            WEBHOOK_SECRET.encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()
        headers["X-Raksha-Signature"] = f"sha256={sig}"

    req = urllib.request.Request(
        WEBHOOK_URL, data=payload, headers=headers, method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        log.info(
            f"[notifier] webhook → HTTP {resp.status} "
            f"for rule {alert.get('rule_id')}"
        )


# ── SMS placeholder ───────────────────────────────────────────────────────────
# Wire to Twilio / AWS SNS by implementing _send_sms(alert) and calling it
# from _dispatch_sync. Example env vars: SMS_TO, TWILIO_SID, TWILIO_TOKEN.
