"""
Raksha Vision Core — Cross-Camera Re-Identification Engine
==========================================================
Soft re-ID using color histograms + geometric signature.
No deep learning model required — works with any detector.

When a track exits camera A and a visually similar track enters camera B
within MAX_TRAVEL_SEC, fires a CROSS_CAMERA_REID alert.
"""

import time
import math
import threading
from typing import Dict, List, Optional, Tuple

import cv2
import numpy as np


# Maximum seconds a fingerprint is kept after exit
MAX_EXIT_AGE   = 180.0
# Maximum time gap between exit and re-entry to count as same person
MAX_TRAVEL_SEC = 120.0
# Minimum similarity score (0–1) to flag a re-ID match
MIN_SIMILARITY = 0.80
# Minimum bbox area to compute a reliable histogram
MIN_AREA = 800


class TrackFingerprint:
    __slots__ = ("cam_id", "cam_name", "zone", "uid", "exit_ts",
                 "hist_h", "hist_s", "avg_aspect", "avg_vel", "dwell_sec")

    def __init__(self, cam_id, cam_name, zone, uid,
                 hist_h, hist_s, avg_aspect, avg_vel, dwell_sec):
        self.cam_id     = cam_id
        self.cam_name   = cam_name
        self.zone       = zone
        self.uid        = uid
        self.exit_ts    = time.time()
        self.hist_h     = hist_h   # normalised hue histogram (32 bins)
        self.hist_s     = hist_s   # normalised saturation histogram (32 bins)
        self.avg_aspect = avg_aspect
        self.avg_vel    = avg_vel
        self.dwell_sec  = dwell_sec


class ReIDEngine:
    def __init__(self):
        self._lock    = threading.Lock()
        self._exits:  List[TrackFingerprint] = []
        self._matched: Dict[str, float] = {}  # uid → last_match_ts (dedup)

    # ── Called by FrameAnalyser when a track goes stale ───────────────────────
    def register_exit(self, cam_id: str, cam_name: str, zone: str,
                      uid: str, frames: List[np.ndarray],
                      avg_aspect: float, avg_vel: float, dwell: float):
        if not frames:
            return
        hist_h, hist_s = self._compute_hist(frames)
        if hist_h is None:
            return
        fp = TrackFingerprint(cam_id, cam_name, zone, uid,
                              hist_h, hist_s, avg_aspect, avg_vel, dwell)
        with self._lock:
            self._purge()
            self._exits.append(fp)

    # ── Called when a new track is mature enough — try to match ───────────────
    def match(self, cam_id: str, uid: str, frames: List[np.ndarray],
              avg_aspect: float, avg_vel: float) -> Optional[dict]:
        if not frames:
            return None
        hist_h, hist_s = self._compute_hist(frames)
        if hist_h is None:
            return None

        now = time.time()
        best_sim, best_fp = 0.0, None

        with self._lock:
            self._purge()
            for fp in self._exits:
                if fp.cam_id == cam_id:
                    continue   # same camera — not a re-ID
                age = now - fp.exit_ts
                if age > MAX_TRAVEL_SEC:
                    continue
                sim = self._similarity(hist_h, hist_s, avg_aspect, avg_vel,
                                       fp.hist_h, fp.hist_s, fp.avg_aspect, fp.avg_vel)
                if sim > best_sim:
                    best_sim, best_fp = sim, fp

        if best_sim < MIN_SIMILARITY or best_fp is None:
            return None

        # Dedup: don't fire for same uid twice within 120s
        dedup_key = f"{best_fp.uid}:{uid}"
        if now - self._matched.get(dedup_key, 0) < 120:
            return None
        self._matched[dedup_key] = now

        return {
            "type":        "ALERT",
            "event_id":    f"REID-{int(now*1000)%100000000}",
            "rule_id":     "REID-001",
            "rule_name":   "Cross-Camera Person Re-Identification",
            "category":    "SECURITY",
            "severity":    "HIGH",
            "risk_score":  int(best_sim * 90),
            "person_id":   uid,
            "matched_uid": best_fp.uid,
            "camera_id":   cam_id,
            "camera_name": "",
            "zone":        "",
            "prev_camera": best_fp.cam_id,
            "prev_zone":   best_fp.zone,
            "travel_sec":  round(now - best_fp.exit_ts, 1),
            "similarity":  round(best_sim, 3),
            "description": (
                f"Person re-identified crossing cameras. "
                f"Last seen at {best_fp.cam_name} ({best_fp.zone}) "
                f"{int(now - best_fp.exit_ts)}s ago. Similarity {best_sim:.0%}."
            ),
            "trigger":  f"color_sim={best_sim:.2f}>{MIN_SIMILARITY}, travel={int(now-best_fp.exit_ts)}s",
            "action":   "Cross-reference footage. Determine if same individual is suspect.",
            "reasons":  ["re-id", "cross-camera", "tracking"],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }

    # ── Helpers ────────────────────────────────────────────────────────────────
    def _compute_hist(self, frames: List[np.ndarray]) -> Tuple[Optional[np.ndarray], Optional[np.ndarray]]:
        hists_h, hists_s = [], []
        for frame in frames:
            if frame is None or frame.size < MIN_AREA:
                continue
            hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
            h = cv2.calcHist([hsv], [0], None, [32], [0, 180])
            s = cv2.calcHist([hsv], [1], None, [32], [0, 256])
            hists_h.append(cv2.normalize(h, h).flatten())
            hists_s.append(cv2.normalize(s, s).flatten())
        if not hists_h:
            return None, None
        return (np.mean(hists_h, axis=0).astype(np.float32),
                np.mean(hists_s, axis=0).astype(np.float32))

    @staticmethod
    def _similarity(h1, s1, ar1, vel1, h2, s2, ar2, vel2) -> float:
        # Color histogram intersection (Bhattacharyya distance → similarity)
        bh_h = float(cv2.compareHist(h1, h2, cv2.HISTCMP_BHATTACHARYYA))
        bh_s = float(cv2.compareHist(s1, s2, cv2.HISTCMP_BHATTACHARYYA))
        color_sim = 1.0 - (0.65 * bh_h + 0.35 * bh_s)
        # Aspect ratio similarity (penalise very different body shapes)
        ar_sim = 1.0 - min(abs(ar1 - ar2) / max(ar1 + ar2, 0.01), 1.0)
        return max(0.0, 0.80 * color_sim + 0.20 * ar_sim)

    def _purge(self):
        cutoff = time.time() - MAX_EXIT_AGE
        self._exits = [fp for fp in self._exits if fp.exit_ts > cutoff]


# Singleton shared across all cameras
REID = ReIDEngine()
