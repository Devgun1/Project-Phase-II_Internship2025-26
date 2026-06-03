"""
Raksha Vision Core — Authentication + RBAC
==========================================
Single-user (env vars) or multi-user (JSON list) credential store.
Tokens are 32-byte URL-safe strings, valid for 24 hours.
No external dependency — pure stdlib.

Single-user config:
  RAKSHA_USER  (default: admin)
  RAKSHA_PASS  (default: raksha2024)
  RAKSHA_ROLE  (default: admin)

Multi-user config — set RAKSHA_USERS to a JSON array:
  RAKSHA_USERS='[{"username":"admin","password":"s3cr3t","role":"admin"},
                 {"username":"ops","password":"ops123","role":"operator"},
                 {"username":"view","password":"view123","role":"viewer"}]'

Roles (highest → lowest):
  admin    — full access (all HTTP methods, all endpoints)
  operator — cameras + alerts read/write; no system config or user management
  viewer   — read-only (GET requests only)
"""

import json
import os
import secrets
import time
from typing import Dict, Optional, Tuple

from fastapi import HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# ── Token store: token → (expiry_ts, role) ───────────────────────────────────
# Persisted to a small JSON file so tokens survive uvicorn --reload restarts.
_TOKEN_TTL  = 86_400  # 24 hours
_TOKEN_FILE = os.path.join(os.path.dirname(__file__), ".token_store.json")
_tokens: Dict[str, Tuple[float, str]] = {}


def _load_tokens():
    """Load persisted tokens from disk on first import."""
    global _tokens
    try:
        with open(_TOKEN_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        now = time.time()
        _tokens = {k: tuple(v) for k, v in raw.items() if v[0] > now}
    except (FileNotFoundError, Exception):
        _tokens = {}


def _save_tokens():
    try:
        with open(_TOKEN_FILE, "w", encoding="utf-8") as f:
            json.dump(_tokens, f)
    except Exception:
        pass


_load_tokens()

AUTH_ENABLED = os.environ.get("RAKSHA_AUTH", "on").lower() not in ("off", "0", "false")

_bearer = HTTPBearer(auto_error=False)

# Role rank — higher number = more privilege
ROLE_HIERARCHY: Dict[str, int] = {
    "admin":    3,
    "operator": 2,
    "viewer":   1,
}


# ── User store ───────────────────────────────────────────────────────────────

def _load_users() -> list:
    """Return user list from RAKSHA_USERS (JSON) or single-user env vars."""
    raw = os.environ.get("RAKSHA_USERS", "").strip()
    if raw:
        try:
            users = json.loads(raw)
            if isinstance(users, list) and users:
                return users
        except Exception:
            pass
    return [{
        "username": os.environ.get("RAKSHA_USER", "admin"),
        "password": os.environ.get("RAKSHA_PASS", "raksha2024"),
        "role":     os.environ.get("RAKSHA_ROLE", "admin"),
    }]


def get_credentials() -> Tuple[str, str]:
    """Return (username, password) of the primary user — backward-compat shim."""
    return (
        os.environ.get("RAKSHA_USER", "admin"),
        os.environ.get("RAKSHA_PASS", "raksha2024"),
    )


# ── Auth operations ──────────────────────────────────────────────────────────

def login(username: str, password: str) -> Optional[str]:
    """
    Validate credentials. Returns a session token on success, None on failure.
    Username comparison is case-insensitive and strips surrounding whitespace.
    """
    users = _load_users()
    matched_role: Optional[str] = None
    for u in users:
        stored_user = str(u.get("username", "")).strip()
        stored_pass = str(u.get("password", ""))
        if stored_user.lower() == username.strip().lower() and stored_pass == password:
            matched_role = str(u.get("role", "viewer")).lower()
            break
    if matched_role is None:
        return None
    token = secrets.token_urlsafe(32)
    _tokens[token] = (time.time() + _TOKEN_TTL, matched_role)
    _purge()
    _save_tokens()
    return token


def verify_token(token: str) -> bool:
    """Return True if token is present and not expired."""
    entry = _tokens.get(token)
    if entry is None:
        return False
    exp, _ = entry
    if time.time() > exp:
        _tokens.pop(token, None)
        return False
    return True


def get_token_role(token: str) -> Optional[str]:
    """Return the role associated with a valid token, or None if invalid/expired."""
    entry = _tokens.get(token)
    if entry is None:
        return None
    exp, role = entry
    if time.time() > exp:
        _tokens.pop(token, None)
        return None
    return role


def revoke_token(token: str):
    _tokens.pop(token, None)
    _save_tokens()


def _purge():
    now = time.time()
    dead = [t for t, (exp, _) in list(_tokens.items()) if exp < now]
    for t in dead:
        _tokens.pop(t, None)


# ── Internal helpers ─────────────────────────────────────────────────────────

def _extract_token(request: Request) -> Optional[str]:
    """Pull token from Authorization: Bearer <token> header or ?token= query param."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return request.query_params.get("token")


def _check_role(request: Request, min_role: str) -> str:
    """
    Internal: verify token and check role meets minimum. Returns role string.
    Raises HTTPException 401 if unauthenticated, 403 if insufficient role.
    """
    if not AUTH_ENABLED:
        return "admin"
    token = _extract_token(request)
    if not token or not verify_token(token):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized — please log in",
            headers={"WWW-Authenticate": "Bearer"},
        )
    role = get_token_role(token)
    if role is None or ROLE_HIERARCHY.get(role, 0) < ROLE_HIERARCHY.get(min_role, 99):
        raise HTTPException(
            status_code=403,
            detail=f"Insufficient permissions — {min_role} or higher required",
        )
    return role


# ── FastAPI dependency functions ─────────────────────────────────────────────

async def require_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = None,
) -> str:
    """Dependency: any authenticated user (viewer+). Returns role string."""
    return _check_role(request, "viewer")


async def require_operator(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = None,
) -> str:
    """Dependency: operator or admin only."""
    return _check_role(request, "operator")


async def require_admin(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = None,
) -> str:
    """Dependency: admin only."""
    return _check_role(request, "admin")
