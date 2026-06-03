"""
Raksha Vision Core — Realistic CCTV Event Simulator
Generates lifelike behavioural events until the real CV pipeline connects.
"""

import asyncio
import json
import random
import time
from datetime import datetime
from typing import Callable, Awaitable

from core_backend.rules.behavioral_rules import ALL_RULES, Severity

# Camera zones in a typical retail/commercial premises
CAMERAS = [
    {"id": "CAM-01", "name": "Main Entrance",        "zone": "Entry/Exit"},
    {"id": "CAM-02", "name": "High-Value Display",   "zone": "Jewellery/Gold"},
    {"id": "CAM-03", "name": "Checkout Area",        "zone": "Checkout"},
    {"id": "CAM-04", "name": "Aisle A — Electronics","zone": "Electronics"},
    {"id": "CAM-05", "name": "Aisle B — Clothing",   "zone": "Clothing"},
    {"id": "CAM-06", "name": "Staff Room Entry",     "zone": "Restricted"},
    {"id": "CAM-07", "name": "Parking Lot",          "zone": "External"},
    {"id": "CAM-08", "name": "Emergency Exit",       "zone": "Entry/Exit"},
]

# Weighted pool: more business events, fewer critical security
RULE_WEIGHTS = {
    "CRITICAL": 2,
    "HIGH":     8,
    "MEDIUM":   18,
    "LOW":      28,
}

_person_counter = 1000


def _new_person_id() -> str:
    global _person_counter
    _person_counter += 1
    return f"PID-{_person_counter}"


def _gender() -> str:
    return random.choice(["Male", "Female"])


def _age_group() -> str:
    return random.choice(["18-25", "26-35", "36-50", "51-65", "65+"])


def _appearance() -> str:
    tops    = ["red jacket", "blue hoodie", "white shirt", "black coat", "grey sweater", "green t-shirt"]
    bottoms = ["jeans", "black trousers", "cargo pants", "dark leggings", "beige shorts"]
    return f"{random.choice(tops)}, {random.choice(bottoms)}"


def _build_event(rule) -> dict:
    cam = random.choice(CAMERAS)
    risk_min, risk_max = rule.risk_range
    risk_score = random.randint(risk_min, risk_max)

    return {
        "event_id":    f"EVT-{int(time.time()*1000) % 1000000}",
        "rule_id":     rule.rule_id,
        "rule_name":   rule.name,
        "category":    rule.category.value,
        "severity":    rule.severity.value,
        "risk_score":  risk_score,
        "person_id":   _new_person_id(),
        "gender":      _gender(),
        "age_group":   _age_group(),
        "appearance":  _appearance(),
        "camera_id":   cam["id"],
        "camera_name": cam["name"],
        "zone":        cam["zone"],
        "description": rule.description,
        "trigger":     rule.trigger,
        "action":      rule.action,
        "reasons":     rule.tags,
        "timestamp":   datetime.now().isoformat(),
        "ts_ms":       int(time.time() * 1000),
    }


def _weighted_random_rule():
    pool = []
    for rule in ALL_RULES:
        w = RULE_WEIGHTS.get(rule.severity.value, 5)
        pool.extend([rule] * w)
    return random.choice(pool)


async def run_simulator(broadcast: Callable[[str], Awaitable[None]]):
    """
    Continuously generates realistic CCTV events and calls broadcast(json_str).
    Interval varies: business events fire frequently, critical ones rarely.
    """
    # Stagger intervals by severity to feel realistic
    intervals = {
        "CRITICAL": (45, 120),
        "HIGH":     (20, 60),
        "MEDIUM":   (8, 25),
        "LOW":      (3, 10),
    }

    # Keep per-rule timers
    rule_next_fire = {r.rule_id: time.time() + random.uniform(2, 15) for r in ALL_RULES}

    while True:
        now = time.time()
        fired = False

        for rule in ALL_RULES:
            if not rule.enabled:
                continue
            if now >= rule_next_fire[rule.rule_id]:
                event = _build_event(rule)
                await broadcast(json.dumps(event))

                lo, hi = intervals[rule.severity.value]
                rule_next_fire[rule.rule_id] = now + random.uniform(lo, hi)
                fired = True
                break   # one event per loop tick

        await asyncio.sleep(2 if fired else 1)


async def run_analytics_ticker(broadcast: Callable[[str], Awaitable[None]]):
    """
    Every 10 seconds emits an analytics snapshot (footfall, conversion, etc.)
    """
    base_footfall  = random.randint(80, 140)
    base_active    = random.randint(8, 22)
    base_conv      = random.uniform(28, 55)

    while True:
        snapshot = {
            "type":            "ANALYTICS_SNAPSHOT",
            "timestamp":       datetime.now().isoformat(),
            "footfall_today":  base_footfall + random.randint(-3, 5),
            "active_persons":  max(1, base_active + random.randint(-2, 3)),
            "conversion_rate": round(base_conv + random.uniform(-2, 2), 1),
            "avg_dwell_min":   round(random.uniform(4.5, 12.0), 1),
            "queue_length":    random.randint(0, 7),
            "alerts_today":    random.randint(12, 40),
            "cameras_online":  len(CAMERAS),
            "zones": [
                {"zone": "Jewellery/Gold",  "traffic": random.randint(3, 18),  "risk": "HIGH"},
                {"zone": "Electronics",     "traffic": random.randint(10, 35), "risk": "MEDIUM"},
                {"zone": "Clothing",        "traffic": random.randint(15, 50), "risk": "LOW"},
                {"zone": "Checkout",        "traffic": random.randint(5, 20),  "risk": "LOW"},
                {"zone": "Entry/Exit",      "traffic": random.randint(20, 60), "risk": "LOW"},
                {"zone": "Restricted",      "traffic": random.randint(0, 3),   "risk": "CRITICAL"},
            ],
        }
        # drift base values slowly
        base_footfall  = max(50, base_footfall + random.randint(-1, 2))
        base_active    = max(1,  base_active   + random.randint(-1, 1))
        base_conv      = max(10, min(90, base_conv + random.uniform(-0.5, 0.5)))

        await broadcast(json.dumps(snapshot))
        await asyncio.sleep(10)
