"""
modules/token_validator.py - Pre-scan Token Health Check

Validates the provided token before scanning begins.
Prevents false-negative scans caused by already-expired or malformed tokens.
"""

import json
import base64
import time
from typing import Dict, Any, Tuple


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def validate_token_health(token: str, token_type: str) -> Tuple[bool, str]:
    """
    Validate a token before scanning.

    Returns:
        (True, message)  — healthy or warning, scan can proceed
        (False, message) — scan should abort
    """
    if token_type == "hmac":
        if not token or len(token) < 10:
            return False, "HMAC token is empty or too short."
        if "." not in token:
            return True, "WARNING: HMAC token has no signature separator — may already be stripped."
        return True, "HMAC token looks well-formed."

    if token_type in ("session", "apikey"):
        if not token or len(token) < 3:
            return False, f"{token_type} token appears empty."
        return True, f"{token_type} token looks well-formed."

    if token_type == "basic":
        if ":" not in token:
            return False, "Basic auth token must be in 'username:password' format."
        return True, "Basic auth credentials look well-formed."

    # JWT / OAuth checks
    parts = token.split(".")
    if len(parts) != 3:
        return False, f"Malformed JWT: expected 3 parts, got {len(parts)}."

    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as e:
        return False, f"Cannot decode JWT payload: {e}"

    now = int(time.time())

    exp = payload.get("exp")
    if exp is None:
        return True, "WARNING: Token has no exp claim. Expiry not enforced by this token."
    if exp < now:
        return False, (
            f"Token EXPIRED {now - exp}s ago (exp={exp}). "
            "All mutations will return the same error. Get a fresh token."
        )
    if exp - now < 120:
        return True, (
            f"WARNING: Token expires in {exp - now}s — may expire mid-scan. "
            "Consider using a longer-lived token."
        )

    iat = payload.get("iat")
    if iat and iat > now + 60:
        return False, f"Token has future iat ({iat}), {iat - now}s from now. Possible clock skew."

    return True, f"Token healthy. Expires in {exp - now}s."


def summarise_token(token: str, token_type: str) -> Dict[str, Any]:
    """Return key claims for display in the scan banner."""
    if token_type == "hmac":
        return {"type": "hmac", "preview": token[:60] + ("..." if len(token) > 60 else "")}
    if token_type == "session":
        return {"type": "session", "cookie_value": token[:40]}
    if token_type == "apikey":
        return {"type": "apikey", "key_preview": token[:20] + "****"}
    if token_type == "basic":
        user = token.split(":")[0]
        return {"type": "basic", "username": user}

    parts = token.split(".")
    if len(parts) != 3:
        return {"type": token_type, "error": "malformed"}
    try:
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return {
            "type":    token_type,
            "alg":     header.get("alg"),
            "sub":     payload.get("sub"),
            "role":    payload.get("role"),
            "exp":     payload.get("exp"),
            "has_jti": "jti" in payload,
            "claims":  list(payload.keys()),
        }
    except Exception:
        return {"type": token_type, "error": "decode failed"}
