"""
SQLite alert persistence for Raksha Vision Core.
Stores every fired alert so history survives restarts.
"""

import sqlite3
import json
import time
from pathlib import Path
from typing import List, Optional

DB_PATH = Path(__file__).parent.parent.parent / "data" / "alerts.db"


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with _conn() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id    TEXT    NOT NULL,
                rule_id     TEXT    NOT NULL,
                rule_name   TEXT    NOT NULL,
                category    TEXT    NOT NULL,
                severity    TEXT    NOT NULL,
                risk_score  INTEGER NOT NULL,
                person_id   TEXT,
                camera_id   TEXT    NOT NULL,
                camera_name TEXT,
                zone        TEXT,
                description TEXT,
                trigger     TEXT,
                action      TEXT,
                reasons     TEXT,
                timestamp   TEXT    NOT NULL,
                stored_at   REAL    NOT NULL
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_camera  ON alerts(camera_id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(stored_at)")


def save_alert(evt: dict):
    with _conn() as con:
        con.execute("""
            INSERT INTO alerts
              (event_id, rule_id, rule_name, category, severity, risk_score,
               person_id, camera_id, camera_name, zone, description,
               trigger, action, reasons, timestamp, stored_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            evt.get("event_id", ""),
            evt.get("rule_id", ""),
            evt.get("rule_name", ""),
            evt.get("category", ""),
            evt.get("severity", ""),
            evt.get("risk_score", 0),
            evt.get("person_id", ""),
            evt.get("camera_id", ""),
            evt.get("camera_name", ""),
            evt.get("zone", ""),
            evt.get("description", ""),
            evt.get("trigger", ""),
            evt.get("action", ""),
            json.dumps(evt.get("reasons", [])),
            evt.get("timestamp", ""),
            time.time(),
        ))


def get_alerts(
    limit: int = 200,
    offset: int = 0,
    camera_id: Optional[str] = None,
    severity: Optional[str] = None,
    since_ts: Optional[float] = None,
) -> List[dict]:
    clauses = []
    params: list = []
    if camera_id:
        clauses.append("camera_id = ?"); params.append(camera_id)
    if severity:
        clauses.append("severity = ?");  params.append(severity)
    if since_ts:
        clauses.append("stored_at >= ?"); params.append(since_ts)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params += [limit, offset]
    with _conn() as con:
        rows = con.execute(
            f"SELECT * FROM alerts {where} ORDER BY stored_at DESC LIMIT ? OFFSET ?",
            params
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["reasons"] = json.loads(d.get("reasons") or "[]")
        out.append(d)
    return out


def get_alert_stats() -> dict:
    with _conn() as con:
        total = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        by_sev = {row[0]: row[1] for row in con.execute(
            "SELECT severity, COUNT(*) FROM alerts GROUP BY severity")}
        today_start = time.time() - 86400
        today = con.execute(
            "SELECT COUNT(*) FROM alerts WHERE stored_at >= ?", (today_start,)
        ).fetchone()[0]
    return {"total": total, "today": today, "by_severity": by_sev}


def purge_old_alerts(days: int = 30):
    cutoff = time.time() - days * 86400
    with _conn() as con:
        con.execute("DELETE FROM alerts WHERE stored_at < ?", (cutoff,))
