"""
extensions/webauthn_sim.py - WebAuthn Challenge Simulation

Simulates WebAuthn signed challenges for testing APIs that use
WebAuthn/FIDO2 authentication. Generates mutations of WebAuthn
assertion objects to test server-side validation.

Based on WebAuthn Level 2 specification (W3C).
"""

import base64
import json
import hashlib
import os
import time
from typing import Dict, Any, List


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


class WebAuthnSimulator:
    """
    Simulates WebAuthn authentication assertions and generates mutations.

    Mutations target common misconfiguration patterns in WebAuthn
    server-side verification:
    - Missing origin validation
    - Replay of old challenges
    - User handle substitution
    - Counter rollback
    - Client data hash manipulation
    """

    def __init__(self, origin: str = "https://example.com", rpid: str = "example.com"):
        """
        Initialize simulator.

        Args:
            origin: WebAuthn origin (RP origin)
            rpid: Relying party ID
        """
        self.origin = origin
        self.rpid = rpid
        self._credential_id = b64url_encode(os.urandom(32))
        self._user_handle = b64url_encode(os.urandom(16))

    def _make_client_data(self, challenge: str, cross_origin: bool = False) -> Dict[str, Any]:
        """Build a clientDataJSON structure."""
        return {
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": self.origin,
            "crossOrigin": cross_origin
        }

    def _make_auth_data(self, user_present: bool = True, user_verified: bool = True,
                        counter: int = 1) -> bytes:
        """
        Build authenticatorData bytes.

        Format: rpIdHash(32) + flags(1) + signCount(4) + extensions
        """
        rp_id_hash = hashlib.sha256(self.rpid.encode()).digest()
        flags = 0
        if user_present:
            flags |= 0x01
        if user_verified:
            flags |= 0x04
        sign_count = counter.to_bytes(4, "big")
        return rp_id_hash + bytes([flags]) + sign_count

    def make_valid_assertion(self, challenge: str = None, counter: int = 1) -> Dict[str, Any]:
        """
        Create a simulated valid WebAuthn assertion.

        Args:
            challenge: Base64url-encoded challenge (random if None)
            counter: Authenticator counter value

        Returns:
            WebAuthn assertion object (as dict)
        """
        challenge = challenge or b64url_encode(os.urandom(32))
        client_data = self._make_client_data(challenge)
        client_data_json = json.dumps(client_data, separators=(",", ":")).encode()
        auth_data = self._make_auth_data(counter=counter)

        # Simulated signature (in real use, this is an ECDSA signature)
        sig_input = auth_data + hashlib.sha256(client_data_json).digest()
        signature = hashlib.sha256(sig_input).digest()  # Mock signature

        return {
            "id": self._credential_id,
            "rawId": self._credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url_encode(client_data_json),
                "authenticatorData": b64url_encode(auth_data),
                "signature": b64url_encode(signature),
                "userHandle": self._user_handle
            }
        }

    def generate_mutations(self, valid_assertion: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Generate mutations of a WebAuthn assertion.

        Args:
            valid_assertion: Valid assertion to mutate (creates one if None)

        Returns:
            List of mutation dicts
        """
        if valid_assertion is None:
            valid_assertion = self.make_valid_assertion()

        mutations = []

        # 1. Wrong origin
        mut = json.loads(json.dumps(valid_assertion))
        client_data = json.loads(b64url_decode(mut["response"]["clientDataJSON"]))
        client_data["origin"] = "https://attacker.com"
        mut["response"]["clientDataJSON"] = b64url_encode(
            json.dumps(client_data, separators=(",", ":")).encode()
        )
        mutations.append({
            "name": "[WebAuthn] Wrong Origin",
            "category": "Algorithm Substitution",
            "token": json.dumps(mut),
            "description": "Changed origin to attacker.com — tests origin validation.",
            "severity_hint": "CRITICAL",
            "mutation_detail": {"technique": "wrong_origin", "origin": "https://attacker.com"}
        })

        # 2. Replay old challenge
        mut2 = json.loads(json.dumps(valid_assertion))
        client_data2 = json.loads(b64url_decode(mut2["response"]["clientDataJSON"]))
        client_data2["challenge"] = b64url_encode(b"old_challenge_replay")
        mut2["response"]["clientDataJSON"] = b64url_encode(
            json.dumps(client_data2, separators=(",", ":")).encode()
        )
        mutations.append({
            "name": "[WebAuthn] Replay Old Challenge",
            "category": "Replay",
            "token": json.dumps(mut2),
            "description": "Replayed a known-old challenge — tests challenge binding.",
            "severity_hint": "HIGH",
            "mutation_detail": {"technique": "challenge_replay"}
        })

        # 3. Counter rollback (set to 0)
        mut3 = json.loads(json.dumps(valid_assertion))
        auth_data_bytes = b64url_decode(mut3["response"]["authenticatorData"])
        # Replace counter bytes (bytes 33-37) with 0
        auth_data_bytes = bytearray(auth_data_bytes)
        auth_data_bytes[33:37] = b"\x00\x00\x00\x00"
        mut3["response"]["authenticatorData"] = b64url_encode(bytes(auth_data_bytes))
        mutations.append({
            "name": "[WebAuthn] Counter Rollback to 0",
            "category": "Replay",
            "token": json.dumps(mut3),
            "description": "Set authenticator counter to 0 — tests counter validation.",
            "severity_hint": "HIGH",
            "mutation_detail": {"counter": 0, "technique": "counter_rollback"}
        })

        # 4. User handle substitution
        mut4 = json.loads(json.dumps(valid_assertion))
        mut4["response"]["userHandle"] = b64url_encode(b"admin")
        mutations.append({
            "name": "[WebAuthn] User Handle = admin",
            "category": "Payload Tampering",
            "token": json.dumps(mut4),
            "description": "Changed userHandle to 'admin' — tests user binding.",
            "severity_hint": "CRITICAL",
            "mutation_detail": {"userHandle": "admin"}
        })

        # 5. Missing UP flag (user presence)
        mut5 = json.loads(json.dumps(valid_assertion))
        auth_data5 = bytearray(b64url_decode(mut5["response"]["authenticatorData"]))
        auth_data5[32] = auth_data5[32] & ~0x01  # Clear UP bit
        mut5["response"]["authenticatorData"] = b64url_encode(bytes(auth_data5))
        mutations.append({
            "name": "[WebAuthn] Missing User Presence Flag",
            "category": "Signature Manipulation",
            "token": json.dumps(mut5),
            "description": "Cleared user presence flag — tests UP enforcement.",
            "severity_hint": "MEDIUM",
            "mutation_detail": {"cleared_flag": "UP"}
        })

        # 6. Empty signature
        mut6 = json.loads(json.dumps(valid_assertion))
        mut6["response"]["signature"] = ""
        mutations.append({
            "name": "[WebAuthn] Empty Signature",
            "category": "Signature Manipulation",
            "token": json.dumps(mut6),
            "description": "Removed assertion signature — tests signature enforcement.",
            "severity_hint": "CRITICAL",
            "mutation_detail": {"technique": "signature_stripped"}
        })

        # 7. Wrong type (webauthn.create instead of webauthn.get)
        mut7 = json.loads(json.dumps(valid_assertion))
        client_data7 = json.loads(b64url_decode(mut7["response"]["clientDataJSON"]))
        client_data7["type"] = "webauthn.create"
        mut7["response"]["clientDataJSON"] = b64url_encode(
            json.dumps(client_data7, separators=(",", ":")).encode()
        )
        mutations.append({
            "name": "[WebAuthn] Wrong Type (webauthn.create)",
            "category": "Payload Tampering",
            "token": json.dumps(mut7),
            "description": "Set type to 'webauthn.create' instead of 'webauthn.get'.",
            "severity_hint": "MEDIUM",
            "mutation_detail": {"type": "webauthn.create"}
        })

        return mutations
