"""
lab/vulnerable_server.py - Intentionally Vulnerable JWT/HMAC Server

A Flask server designed for security research and testing the scanner.
Contains intentional misconfigurations for demonstration purposes.

WARNING: This server is INTENTIONALLY VULNERABLE. Never deploy in production.

Run:
    python lab/vulnerable_server.py
    # Server starts on http://localhost:5000
"""

import hashlib
import hmac
import json
import time
import base64
import os

from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# ── Shared state ─────────────────────────────────────────────────────────────

USERS_DB = {
    "user123": {"role": "user", "name": "Alice", "email": "alice@test.com"},
    "admin": {"role": "admin", "name": "Admin", "email": "admin@test.com"},
}

HMAC_SECRET = "secret"  # Intentionally weak secret for testing

# Admin data — only accessible with valid admin token
ADMIN_DATA = {
    "users": list(USERS_DB.values()),
    "system": {"version": "1.0", "uptime": "3 days"},
    "config": {"debug": True, "db_host": "localhost"},
}

# ── JWT helpers ───────────────────────────────────────────────────────────────

def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def create_valid_jwt(user_id: str = "user123", role: str = "user") -> str:
    """Create a valid HS256-signed JWT for testing."""
    import hmac as hmac_lib

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "jti": os.urandom(8).hex(),
    }

    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac_lib.new("jwt_strong_secret_32bytes!".encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


# ── Vulnerable endpoint helpers ───────────────────────────────────────────────

class VulnerabilityConfig:
    """Toggle which vulnerabilities are active."""
    ALG_NONE_BYPASS = True       # Accept alg:none
    EXP_NOT_VALIDATED = True     # Don't check exp claim
    HMAC_WEAK_SECRET = True      # Use "secret" as HMAC key
    SIGNATURE_NOT_CHECKED = False  # Skip sig check entirely (too obvious)
    ROLE_FROM_TOKEN = True       # Trust role claim without verification


vuln_config = VulnerabilityConfig()


def verify_jwt_vulnerable(token: str) -> dict:
    """
    VULNERABLE JWT verification — used for testing.
    Intentionally misconfigured in various ways.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"valid": False, "reason": "malformed"}

        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))

        alg = header.get("alg", "").lower()

        # VULNERABILITY 1: Accept alg:none
        if vuln_config.ALG_NONE_BYPASS and alg in ("none", "NONE", "None", "nOnE"):
            pass  # Skip signature verification!

        # VULNERABILITY 2: Don't check expiration
        if not vuln_config.EXP_NOT_VALIDATED:
            exp = payload.get("exp", 0)
            if exp and exp < time.time():
                return {"valid": False, "reason": "expired"}

        # VULNERABILITY 3: Trust role from token
        role = payload.get("role", "user") if vuln_config.ROLE_FROM_TOKEN else "user"
        sub = payload.get("sub", "unknown")

        return {"valid": True, "sub": sub, "role": role, "payload": payload}

    except Exception as e:
        return {"valid": False, "reason": str(e)}


def verify_hmac_vulnerable(token: str) -> dict:
    """
    VULNERABLE HMAC verification — weak secret, truncation allowed.
    """
    try:
        if "." not in token:
            # No signature at all — pass through if SIGNATURE_NOT_CHECKED
            if vuln_config.SIGNATURE_NOT_CHECKED:
                return {"valid": True, "message": token, "role": "user"}
            return {"valid": False, "reason": "missing_signature"}

        parts = token.rsplit(".", 1)
        message_str = parts[0]
        provided_sig = parts[1]

        # Try to parse message as JSON
        try:
            message_data = json.loads(message_str)
            role = message_data.get("role", "user")
            user_id = message_data.get("user_id", "user123")
        except Exception:
            message_data = {}
            role = "user"
            user_id = "unknown"

        if vuln_config.HMAC_WEAK_SECRET:
            secret = HMAC_SECRET  # "secret" — intentionally weak
        else:
            secret = os.environ.get("HMAC_SECRET", "strong_random_secret_here_256bit!")

        # Compute expected signature
        expected_sig_bytes = hmac.new(
            secret.encode(), message_str.encode(), hashlib.sha256
        ).digest()
        expected_sig = b64url_encode(expected_sig_bytes)

        # VULNERABILITY: Truncated comparison (check only first N chars)
        truncation_len = len(provided_sig)
        if hmac.compare_digest(
            expected_sig[:truncation_len], provided_sig[:truncation_len]
        ):
            return {"valid": True, "user_id": user_id, "role": role, "message": message_data}

        return {"valid": False, "reason": "invalid_signature"}

    except Exception as e:
        return {"valid": False, "reason": str(e)}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint — no auth required."""
    return jsonify({"status": "ok", "timestamp": time.time()})


@app.route("/token", methods=["POST"])
def get_token():
    """Issue a valid JWT for testing."""
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id", "user123")
    role = USERS_DB.get(user_id, {}).get("role", "user")
    token = create_valid_jwt(user_id=user_id, role=role)
    return jsonify({
        "token": token,
        "user_id": user_id,
        "role": role,
        "expires_in": 3600
    })


@app.route("/api/profile", methods=["GET"])
def profile():
    """User profile — requires valid JWT (any role)."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Unauthorized", "code": 401}), 401

    token = auth[7:]
    result = verify_jwt_vulnerable(token)

    if not result["valid"]:
        return jsonify({"error": "Invalid token", "reason": result.get("reason")}), 401

    user_data = USERS_DB.get(result["sub"], {"name": "Unknown", "email": "unknown@test.com"})
    return jsonify({
        "success": True,
        "user_id": result["sub"],
        "role": result["role"],
        **user_data
    })


@app.route("/api/admin", methods=["GET"])
def admin():
    """Admin endpoint — requires admin role in JWT."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401

    token = auth[7:]
    result = verify_jwt_vulnerable(token)

    if not result["valid"]:
        return jsonify({"error": "Invalid token"}), 401

    # VULNERABILITY: Role check trusts token payload
    if result.get("role") != "admin":
        return jsonify({"error": "Forbidden", "required": "admin"}), 403

    return jsonify({
        "success": True,
        "admin_data": ADMIN_DATA,
        "is_admin": True,
        "role": "admin"
    })


@app.route("/api/hmac/data", methods=["GET"])
def hmac_data():
    """HMAC-protected endpoint."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("HMAC "):
        return jsonify({"error": "Unauthorized", "expected": "HMAC <token>"}), 401

    token = auth[5:]
    result = verify_hmac_vulnerable(token)

    if not result["valid"]:
        return jsonify({"error": "Invalid HMAC signature", "reason": result.get("reason")}), 401

    return jsonify({
        "success": True,
        "data": {"records": [1, 2, 3], "total": 3},
        "user_role": result.get("role", "user")
    })


@app.route("/api/hmac/admin", methods=["GET"])
def hmac_admin():
    """HMAC-protected admin endpoint."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("HMAC "):
        return jsonify({"error": "Unauthorized"}), 401

    token = auth[5:]
    result = verify_hmac_vulnerable(token)

    if not result["valid"]:
        return jsonify({"error": "Invalid HMAC signature"}), 401

    if result.get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403

    return jsonify({
        "success": True,
        "admin_data": ADMIN_DATA,
        "role": "admin",
        "is_admin": True
    })


@app.route("/api/strict/admin", methods=["GET"])
def strict_admin():
    """
    Properly secured admin endpoint (for false-positive benchmarking).
    Uses server-side role lookup instead of trusting token.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401

    token = auth[7:]
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("malformed")
        header = json.loads(b64url_decode(parts[0]))
        if header.get("alg", "").lower() == "none":
            raise ValueError("alg:none rejected")

        import hmac as hmac_lib
        payload = json.loads(b64url_decode(parts[1]))
        h = parts[0]
        p = parts[1]
        signing_input = f"{h}.{p}".encode()
        expected_sig = hmac_lib.new(
            "jwt_strong_secret_32bytes!".encode(), signing_input, hashlib.sha256
        ).digest()
        provided_sig = b64url_decode(parts[2])
        if not hmac_lib.compare_digest(expected_sig, provided_sig):
            raise ValueError("invalid signature")

        # Check expiration
        exp = payload.get("exp", 0)
        if exp < time.time():
            raise ValueError("token expired")

        sub = payload.get("sub", "")
        user = USERS_DB.get(sub)
        if user is None or user.get("role") != "admin":
            return jsonify({"error": "Forbidden"}), 403

        return jsonify({"success": True, "message": "Properly secured endpoint", "admin_data": ADMIN_DATA})

    except ValueError as e:
        return jsonify({"error": "Invalid token", "reason": str(e)}), 401


# ── Session store (in-memory) ─────────────────────────────────────────────────
import secrets as _secrets

SESSION_STORE = {
    "admin_session_fixed": "admin",   # VULNERABILITY: predictable/fixed session ID
    "user_session_00001":  "user",    # VULNERABILITY: sequential integer-style ID
}


@app.route("/", methods=["GET"])
def index():
    """Root dashboard for the lab server."""
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel Lab - Vulnerable Target</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root { --bg: #0a0a0f; --surface: #14141f; --primary: #00f2ff; --secondary: #7000ff; --text: #e0e0e0; --text-dim: #94a3b8; }
        body { font-family: 'Outfit', sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 40px 20px; text-align: center; }
        .container { max-width: 900px; margin: 0 auto; }
        .header { margin-bottom: 40px; }
        h1 { font-size: 3rem; margin: 0; background: linear-gradient(90deg, var(--primary), var(--secondary)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .status-badge { display: inline-block; padding: 6px 16px; border-radius: 20px; background: rgba(0, 242, 255, 0.1); color: var(--primary); border: 1px solid var(--primary); font-size: 0.9rem; margin-top: 10px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-top: 40px; }
        .card { background: var(--surface); padding: 30px; border-radius: 24px; border: 1px solid rgba(255,255,255,0.05); text-align: left; transition: transform 0.2s; }
        .card:hover { transform: translateY(-5px); border-color: var(--primary); }
        .card h3 { color: #fff; margin-top: 0; display: flex; align-items: center; gap: 10px; }
        .card p { color: var(--text-dim); font-size: 0.9rem; line-height: 1.5; }
        code { background: #000; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: var(--primary); font-size: 0.85rem; }
        .endpoint-list { list-style: none; padding: 0; margin-top: 15px; }
        .endpoint-list li { font-size: 0.85rem; margin-bottom: 8px; color: #fff; display: flex; justify-content: space-between; }
        .method { font-weight: bold; color: var(--secondary); font-size: 0.75rem; border: 1px solid var(--secondary); padding: 1px 4px; border-radius: 4px; margin-right: 8px; }
        .vuln-tags { margin-top: 10px; }
        .tag { font-size: 0.7rem; background: #331122; color: #ff55aa; padding: 2px 8px; border-radius: 10px; margin-right: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>Sentinel Lab Target</h1>
            <div class="status-badge">● STAGING ENVIRONMENT (VULNERABLE)</div>
        </header>

        <p style="color: var(--text-dim);">This server is intentionally misconfigured for security research purposes.<br>Use the Sentinel CLI scanner to identify and exploit these vulnerabilities.</p>

        <div class="grid">
            <div class="card">
                <h3><span>🔑</span> JWT Layer</h3>
                <p>Standard bearer token authentication with multiple signature and payload flaws.</p>
                <ul class="endpoint-list">
                    <li><span><span class="method">GET</span> <code>/api/profile</code></span> <span>(User)</span></li>
                    <li><span><span class="method">GET</span> <code>/api/admin</code></span> <span>(Admin)</span></li>
                </ul>
                <div class="vuln-tags">
                    <span class="tag">alg:none</span><span class="tag">weak-validation</span><span class="tag">role-tampering</span>
                </div>
            </div>

            <div class="card">
                <h3><span>🔒</span> HMAC Layer</h3>
                <p>Message-integrity-based auth using shared secrets and custom signature headers.</p>
                <ul class="endpoint-list">
                    <li><span><span class="method">GET</span> <code>/api/hmac/data</code></span> <span>(All)</span></li>
                    <li><span><span class="method">GET</span> <code>/api/hmac/admin</code></span> <span>(Admin)</span></li>
                </ul>
                <div class="vuln-tags">
                    <span class="tag">weak-secret</span><span class="tag">truncation</span><span class="tag">timing-oracle</span>
                </div>
            </div>

            <div class="card">
                <h3><span>🍪</span> Session & Key</h3>
                <p>Legacy session management and simple API key header authentication.</p>
                <ul class="endpoint-list">
                    <li><span><span class="method">GET</span> <code>/api/session/admin</code></span> <span>(Cookie)</span></li>
                    <li><span><span class="method">GET</span> <code>/api/data</code></span> <span>(API Key)</span></li>
                </ul>
                <div class="vuln-tags">
                    <span class="tag">sequential-ids</span><span class="tag">default-keys</span><span class="tag">insecure-flags</span>
                </div>
            </div>
        </div>

        <footer style="margin-top: 60px; color: #444; font-size: 0.8rem;">
            RESEARCH USE ONLY | Sentinel Lab v2.1.0
        </footer>
    </div>
</body>
</html>"""
    return html


@app.route("/api/session/login", methods=["POST"])
def session_login():
    """Issue a session cookie on valid login.
    VULNERABLE: short/predictable session IDs, missing Secure/HttpOnly flags."""
    data    = request.get_json(silent=True) or {}
    user_id = data.get("user_id", "user123")
    role    = USERS_DB.get(user_id, {}).get("role", "user")
    # VULNERABILITY: low-entropy 4-char hex suffix
    session_id = f"{'admin' if role == 'admin' else 'user'}_session_{_secrets.token_hex(2)}"
    SESSION_STORE[session_id] = role
    resp = make_response(jsonify({"success": True, "user_id": user_id, "session_id": session_id}))
    resp.set_cookie("sessionid", session_id, httponly=False, secure=False)  # Missing flags
    return resp


@app.route("/api/session/admin", methods=["GET"])
def session_admin():
    """Session-protected admin endpoint."""
    session_id = request.cookies.get("sessionid", "")
    if not session_id:
        return jsonify({"error": "No session"}), 401
    role = SESSION_STORE.get(session_id)
    if not role:
        return jsonify({"error": "Invalid session"}), 401
    if role != "admin":
        return jsonify({"error": "Forbidden"}), 403
    return jsonify({"success": True, "admin_data": ADMIN_DATA, "is_admin": True, "role": "admin"})


@app.route("/api/data", methods=["GET"])
def apikey_data():
    """API key protected endpoint.
    VULNERABLE: accepts weak default keys like 'test', 'demo', 'admin'."""
    key = request.headers.get("X-API-Key", request.args.get("api_key", ""))
    weak_keys = {"test", "demo", "admin", "secret", "key", "apikey", "api_key",
                 "12345678", "password", "changeme", "default"}
    if not key:
        return jsonify({"error": "Missing API key"}), 401
    if key in weak_keys:
        return jsonify({"success": True, "data": ADMIN_DATA, "is_admin": True})
    return jsonify({"error": "Invalid API key"}), 403


@app.route("/api/oauth/resource", methods=["GET"])
def oauth_resource():
    """OAuth 2.0 protected resource.
    VULNERABLE: does not validate iss, aud, or signature. Trusts scope from token."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    token  = auth[7:]
    parts  = token.split(".")
    if len(parts) != 3:
        return jsonify({"error": "Invalid token format"}), 401
    try:
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        return jsonify({"error": "Cannot decode token"}), 401

    scope = payload.get("scope", payload.get("scp", "read"))
    sub   = payload.get("sub", "unknown")

    if "admin" in str(scope):
        return jsonify({
            "success": True, "sub": sub, "scope": scope,
            "admin_resources": ADMIN_DATA, "is_admin": True,
        })
    return jsonify({
        "success": True, "sub": sub, "scope": scope,
        "data": {"message": f"Hello {sub}, scope: {scope}"},
    })


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    print(f"⚠️  Starting VULNERABLE test server on http://localhost:{port}")
    print("   For security research only. Do NOT deploy in production!")
    app.run(host="127.0.0.1", port=port, debug=False)
