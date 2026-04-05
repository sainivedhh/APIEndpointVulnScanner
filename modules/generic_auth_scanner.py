"""
modules/generic_auth_scanner.py - Non-JWT/HMAC Authentication Scanner

Handles session cookies, API keys, Basic Auth, and opaque tokens.
Generates mutations appropriate for each auth type.

Supported types:
  - SessionCookieMutator  : PHP/Django/Rails session cookies
  - APIKeyMutator         : X-API-Key / query param key auth
  - BasicAuthMutator      : HTTP Basic Authentication
  - detect_auth_type()    : Auto-detect from baseline response headers
"""

import base64
import secrets
from typing import List, Dict, Any, Optional


# ── Common wordlists ──────────────────────────────────────────────────────────

COMMON_API_KEYS = [
    "test", "demo", "admin", "secret", "key", "apikey", "api_key",
    "12345678", "password", "changeme", "default", "master",
    "guest", "public", "readonly", "staging", "development",
    "test_key", "demo_key", "api_test", "hello", "letmein",
]

COMMON_SESSION_IDS = [
    "admin", "0", "1", "root", "guest", "test",
    "0" * 32, "1" * 32, "a" * 32,
    "admin_session_fixed",
    "user_session_00001",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
]


# ── Session Cookie Mutator ────────────────────────────────────────────────────

class SessionCookieMutator:
    """
    Generates session cookie mutations.

    Targets:
    - Session ID prediction (sequential, short, low-entropy)
    - Session fixation (attacker-chosen session ID)
    - Admin session ID guessing from common values
    - Prefix/suffix manipulation
    """

    def __init__(self, cookie_name: str, cookie_value: str, verbose: bool = False):
        self.cookie_name  = cookie_name
        self.cookie_value = cookie_value
        self.verbose      = verbose

    def mut_null_session(self) -> Dict[str, Any]:
        """Send empty session value — tests if server handles missing session."""
        return {
            "name": "Session: Empty value",
            "category": "Session-Cookie",
            "token": "",
            "cookie_name": self.cookie_name,
            "description": "Sends an empty session cookie value.",
            "severity_hint": "MEDIUM",
            "mutation_detail": {"technique": "empty_session"},
        }

    def mut_admin_session_guess(self) -> List[Dict[str, Any]]:
        """Try predictable/common admin session IDs."""
        mutations = []
        for val in COMMON_SESSION_IDS:
            mutations.append({
                "name": f"Session: Predictable ID '{val[:20]}'",
                "category": "Session-Cookie",
                "token": val,
                "cookie_name": self.cookie_name,
                "description": f"Try predictable session value '{val[:20]}'.",
                "severity_hint": "HIGH",
                "mutation_detail": {"guessed_value": val},
            })
        return mutations

    def mut_integer_id_walk(self) -> List[Dict[str, Any]]:
        """
        If session ID looks numeric, walk nearby integers.
        Tests sequential/predictable session generation.
        """
        mutations = []
        try:
            numeric_val = int(self.cookie_value)
            for offset in [-2, -1, 1, 2, 100, -100, 1000]:
                candidate = str(numeric_val + offset)
                mutations.append({
                    "name": f"Session: Integer walk ({candidate})",
                    "category": "Session-Cookie",
                    "token": candidate,
                    "cookie_name": self.cookie_name,
                    "description": f"Incremented session ID by {offset} → {candidate}.",
                    "severity_hint": "CRITICAL",
                    "mutation_detail": {
                        "original": self.cookie_value,
                        "candidate": candidate,
                        "offset": offset,
                    },
                })
        except ValueError:
            pass
        return mutations

    def mut_prefix_suffix_variations(self) -> List[Dict[str, Any]]:
        """Try admin/root prefixes on the session value."""
        mutations = []
        val = self.cookie_value
        for variant in [
            f"admin_{val}", f"root_{val}",
            val.upper(), val.lower(),
            val + "_admin", "admin",
        ]:
            mutations.append({
                "name": f"Session: Variant '{variant[:30]}'",
                "category": "Session-Cookie",
                "token": variant,
                "cookie_name": self.cookie_name,
                "description": f"Modified session value: '{variant[:30]}'.",
                "severity_hint": "MEDIUM",
                "mutation_detail": {"variant": variant},
            })
        return mutations

    def generate_all_mutations(self) -> List[Dict[str, Any]]:
        mutations = []
        mutations.append(self.mut_null_session())
        mutations.extend(self.mut_admin_session_guess())
        mutations.extend(self.mut_integer_id_walk())
        mutations.extend(self.mut_prefix_suffix_variations())
        return mutations


# ── API Key Mutator ───────────────────────────────────────────────────────────

class APIKeyMutator:
    """
    Generates API key mutations.

    Targets:
    - Missing key (no auth header)
    - Weak/default API keys
    - Key format manipulation (prefix stripping, env swapping)
    - Query param delivery instead of header
    """

    def __init__(
        self,
        api_key: str,
        header_name: str = "X-API-Key",
        query_param: Optional[str] = None,
        verbose: bool = False,
    ):
        self.api_key     = api_key
        self.header_name = header_name
        self.query_param = query_param
        self.verbose     = verbose

    def mut_no_key(self) -> Dict[str, Any]:
        """Send request with no API key — tests if endpoint is actually protected."""
        return {
            "name": "API Key: Missing (no key sent)",
            "category": "API-Key",
            "token": "",
            "header_name": self.header_name,
            "description": "Sends request with no API key header.",
            "severity_hint": "CRITICAL",
            "mutation_detail": {"technique": "no_key"},
        }

    def mut_empty_key(self) -> Dict[str, Any]:
        """Send empty/whitespace string as API key."""
        return {
            "name": "API Key: Empty string",
            "category": "API-Key",
            "token": " ",
            "header_name": self.header_name,
            "description": "Sends a blank API key value.",
            "severity_hint": "HIGH",
            "mutation_detail": {"technique": "empty_key"},
        }

    def mut_common_keys(self) -> List[Dict[str, Any]]:
        """Try common/default API key values."""
        mutations = []
        for key in COMMON_API_KEYS:
            mutations.append({
                "name": f"API Key: Common key '{key}'",
                "category": "API-Key",
                "token": key,
                "header_name": self.header_name,
                "description": f"Tried common API key '{key}'.",
                "severity_hint": "HIGH",
                "mutation_detail": {"guessed_key": key},
            })
        return mutations

    def mut_strip_prefix(self) -> List[Dict[str, Any]]:
        """Strip common prefixes — tests if server validates only the suffix."""
        mutations = []
        for prefix in ["sk_live_", "sk_test_", "pk_live_", "Bearer ", "Token ", "key_", "apikey_"]:
            if self.api_key.startswith(prefix):
                stripped = self.api_key[len(prefix):]
                mutations.append({
                    "name": f"API Key: Strip prefix '{prefix.strip()}'",
                    "category": "API-Key",
                    "token": stripped,
                    "header_name": self.header_name,
                    "description": f"Stripped prefix '{prefix}' from key.",
                    "severity_hint": "MEDIUM",
                    "mutation_detail": {"prefix_stripped": prefix, "result": stripped[:20]},
                })
        return mutations

    def mut_env_swap(self) -> List[Dict[str, Any]]:
        """Swap test/live environment segment in the key."""
        mutations = []
        swaps = [
            ("test", "live"), ("live", "test"),
            ("dev", "prod"), ("prod", "dev"),
            ("staging", "prod"), ("sandbox", "production"),
        ]
        for old, new in swaps:
            if old in self.api_key:
                swapped = self.api_key.replace(old, new, 1)
                mutations.append({
                    "name": f"API Key: Env swap '{old}'→'{new}'",
                    "category": "API-Key",
                    "token": swapped,
                    "header_name": self.header_name,
                    "description": f"Swapped environment segment '{old}' → '{new}'.",
                    "severity_hint": "HIGH",
                    "mutation_detail": {"swap": f"{old}→{new}", "result": swapped[:30]},
                })
        return mutations

    def generate_all_mutations(self) -> List[Dict[str, Any]]:
        mutations = []
        mutations.append(self.mut_no_key())
        mutations.append(self.mut_empty_key())
        mutations.extend(self.mut_common_keys())
        mutations.extend(self.mut_strip_prefix())
        mutations.extend(self.mut_env_swap())
        return mutations


# ── Basic Auth Mutator ────────────────────────────────────────────────────────

class BasicAuthMutator:
    """
    Generates Basic Auth mutations.

    Basic Auth format: Authorization: Basic base64(username:password)

    Targets:
    - Default credential pairs (admin:admin, root:root, etc.)
    - Admin username with known password
    - Null/empty password bypass
    - Username enumeration
    """

    COMMON_CREDENTIALS = [
        ("admin",         "admin"),
        ("admin",         "password"),
        ("admin",         ""),
        ("admin",         "123456"),
        ("root",          "root"),
        ("root",          ""),
        ("user",          "user"),
        ("test",          "test"),
        ("guest",         "guest"),
        ("administrator", "administrator"),
        ("admin",         "admin123"),
        ("superadmin",    "superadmin"),
    ]

    def __init__(self, username: str, password: str, verbose: bool = False):
        self.username = username
        self.password = password
        self.verbose  = verbose

    def _encode(self, user: str, pwd: str) -> str:
        return base64.b64encode(f"{user}:{pwd}".encode()).decode()

    def mut_default_credentials(self) -> List[Dict[str, Any]]:
        """Try common username:password combinations."""
        mutations = []
        for user, pwd in self.COMMON_CREDENTIALS:
            encoded = self._encode(user, pwd)
            mutations.append({
                "name": f"Basic Auth: {user}:{pwd if pwd else '(empty)'}",
                "category": "Basic-Auth",
                "token": f"Basic {encoded}",
                "description": f"Tried default credentials {user}:{pwd or '(empty)'}.",
                "severity_hint": "CRITICAL",
                "mutation_detail": {"username": user, "password": pwd or "(empty)"},
            })
        return mutations

    def mut_admin_variants(self) -> List[Dict[str, Any]]:
        """Keep known password, try admin usernames."""
        mutations = []
        for admin_user in ["admin", "root", "administrator", "superadmin"]:
            if admin_user == self.username:
                continue
            encoded = self._encode(admin_user, self.password)
            mutations.append({
                "name": f"Basic Auth: Admin user '{admin_user}' + original password",
                "category": "Basic-Auth",
                "token": f"Basic {encoded}",
                "description": f"Using admin username '{admin_user}' with known password.",
                "severity_hint": "HIGH",
                "mutation_detail": {"username": admin_user, "password": "(original)"},
            })
        return mutations

    def mut_null_password(self) -> Dict[str, Any]:
        """Try original username with empty password."""
        encoded = self._encode(self.username, "")
        return {
            "name": f"Basic Auth: Empty password for '{self.username}'",
            "category": "Basic-Auth",
            "token": f"Basic {encoded}",
            "description": "Sent null/empty password for the known username.",
            "severity_hint": "HIGH",
            "mutation_detail": {"username": self.username, "password": "(empty)"},
        }

    def generate_all_mutations(self) -> List[Dict[str, Any]]:
        mutations = []
        mutations.extend(self.mut_default_credentials())
        mutations.extend(self.mut_admin_variants())
        mutations.append(self.mut_null_password())
        return mutations


# ── Auto-detect auth type ─────────────────────────────────────────────────────

def detect_auth_type(response: Dict[str, Any]) -> str:
    """
    Infer the authentication mechanism from a baseline response.

    Returns one of: 'jwt', 'hmac', 'session', 'apikey', 'basic', 'unknown'
    """
    headers    = response.get("headers", {})
    raw_body   = response.get("raw_body", "").lower()
    www_auth   = headers.get("WWW-Authenticate", headers.get("www-authenticate", ""))
    set_cookie = headers.get("Set-Cookie", headers.get("set-cookie", ""))

    if "bearer" in www_auth.lower():
        return "jwt"
    if "basic" in www_auth.lower():
        return "basic"
    if "hmac" in www_auth.lower():
        return "hmac"
    if set_cookie and any(
        k in set_cookie.lower()
        for k in ["session", "sessionid", "sid", "phpsessid", "jsessionid", "connect.sid"]
    ):
        return "session"
    if (
        "x-api-key" in str(headers).lower()
        or "api_key" in raw_body
        or "api-key" in raw_body
    ):
        return "apikey"

    return "unknown"
