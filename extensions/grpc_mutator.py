"""
extensions/grpc_mutator.py - gRPC/Protobuf-Aware Mutation Extension

Provides proto-aware token mutations for gRPC APIs that use JWT or HMAC
authentication in metadata. Supports both unary and streaming mutations.

Usage:
    from extensions.grpc_mutator import GRPCMutator
    mutator = GRPCMutator(target="localhost:50051", metadata_key="authorization")
    mutations = mutator.generate_mutations(valid_token)
"""

import json
import base64
from typing import List, Dict, Any, Optional


class GRPCMetadataMutation:
    """Represents a gRPC metadata-level token mutation."""

    def __init__(self, name: str, category: str, metadata: Dict[str, str],
                 description: str, severity_hint: str = "HIGH"):
        self.name = name
        self.category = category
        self.metadata = metadata
        self.description = description
        self.severity_hint = severity_hint

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "token": self.metadata.get("authorization", ""),
            "metadata": self.metadata,
            "description": self.description,
            "severity_hint": self.severity_hint,
            "mutation_detail": {"transport": "grpc", "metadata_key": "authorization"}
        }


class GRPCMutator:
    """
    Generates gRPC metadata-level token mutations.

    gRPC uses metadata (analogous to HTTP headers) for auth.
    This mutator wraps JWT/HMAC mutations for gRPC delivery.

    Note: Requires grpcio to be installed for actual gRPC calls.
    The mutation generation works without grpcio.
    """

    def __init__(
        self,
        target: str = "localhost:50051",
        metadata_key: str = "authorization",
        use_tls: bool = False,
        verbose: bool = False
    ):
        """
        Initialize gRPC mutator.

        Args:
            target: gRPC server address (host:port)
            metadata_key: Metadata key for auth token
            use_tls: Use TLS/SSL for connection
            verbose: Verbose output
        """
        self.target = target
        self.metadata_key = metadata_key
        self.use_tls = use_tls
        self.verbose = verbose
        self._channel = None
        self._grpc_available = self._check_grpc()

    def _check_grpc(self) -> bool:
        """Check if grpcio is available."""
        try:
            import grpc  # noqa
            return True
        except ImportError:
            return False

    def generate_mutations(self, valid_token: str, token_type: str = "jwt") -> List[Dict[str, Any]]:
        """
        Generate gRPC metadata mutations from a valid token.

        Args:
            valid_token: Valid JWT or HMAC token
            token_type: 'jwt' or 'hmac'

        Returns:
            List of mutation dicts compatible with scanner format
        """
        from modules.mutator import JWTMutator, HMACMutator

        # Generate base mutations
        if token_type == "jwt":
            base_mutator = JWTMutator(valid_token)
            base_mutations = base_mutator.generate_all_mutations()
        else:
            base_mutator = HMACMutator(valid_token)
            base_mutations = base_mutator.generate_all_mutations()

        # Wrap mutations for gRPC metadata delivery
        grpc_mutations = []
        for mut in base_mutations:
            token = mut["token"]
            prefix = "Bearer " if token_type == "jwt" else "HMAC "
            metadata = {
                self.metadata_key: f"{prefix}{token}",
                "content-type": "application/grpc",
            }
            grpc_mut = dict(mut)
            grpc_mut["name"] = f"[gRPC] {mut['name']}"
            grpc_mut["metadata"] = metadata
            grpc_mut["transport"] = "grpc"
            grpc_mut["mutation_detail"] = dict(mut.get("mutation_detail", {}))
            grpc_mut["mutation_detail"]["transport"] = "grpc"
            grpc_mutations.append(grpc_mut)

        # Add gRPC-specific mutations
        grpc_mutations.extend(self._grpc_specific_mutations(valid_token, token_type))

        return grpc_mutations

    def _grpc_specific_mutations(self, token: str, token_type: str) -> List[Dict[str, Any]]:
        """Generate gRPC-specific mutations not applicable to HTTP."""
        mutations = []

        # Metadata key case variations (gRPC metadata keys are case-insensitive in HTTP/2)
        for key_variant in ["Authorization", "AUTHORIZATION", "authorization", "auth"]:
            prefix = "Bearer " if token_type == "jwt" else "HMAC "
            mutations.append({
                "name": f"[gRPC] Metadata Key Variant: {key_variant}",
                "category": "Algorithm Substitution",
                "token": token,
                "metadata": {key_variant: f"{prefix}{token}"},
                "description": f"Send auth in '{key_variant}' metadata key (case variant).",
                "severity_hint": "LOW",
                "transport": "grpc",
                "mutation_detail": {"key_variant": key_variant, "transport": "grpc"}
            })

        # Missing auth metadata
        mutations.append({
            "name": "[gRPC] No Authorization Metadata",
            "category": "Signature Manipulation",
            "token": "",
            "metadata": {},
            "description": "Send gRPC request with no authorization metadata.",
            "severity_hint": "HIGH",
            "transport": "grpc",
            "mutation_detail": {"technique": "no_auth_metadata"}
        })

        return mutations

    def send_grpc_mutation(
        self,
        stub_class,
        method_name: str,
        request_message,
        mutation: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Send a mutated gRPC request.

        Args:
            stub_class: gRPC stub class
            method_name: RPC method name
            request_message: Protobuf request message
            mutation: Mutation dict with metadata

        Returns:
            Response dict or None on error
        """
        if not self._grpc_available:
            return {"error": "grpcio not installed", "status_code": 0}

        import grpc
        import time

        try:
            if self.use_tls:
                channel = grpc.secure_channel(self.target, grpc.ssl_channel_credentials())
            else:
                channel = grpc.insecure_channel(self.target)

            stub = stub_class(channel)
            metadata = list(mutation.get("metadata", {}).items())

            start = time.time()
            method = getattr(stub, method_name)
            response = method(request_message, metadata=metadata, timeout=10)
            elapsed = (time.time() - start) * 1000

            return {
                "status_code": 200,
                "body": {"grpc_response": str(response)},
                "raw_body": str(response)[:2000],
                "response_time_ms": elapsed,
                "transport": "grpc"
            }

        except Exception as e:
            # Map gRPC status codes to HTTP-like codes
            code_map = {
                "UNAUTHENTICATED": 401,
                "PERMISSION_DENIED": 403,
                "NOT_FOUND": 404,
                "UNAVAILABLE": 503,
            }
            error_str = str(e)
            status = 500
            for grpc_code, http_code in code_map.items():
                if grpc_code in error_str.upper():
                    status = http_code
                    break

            return {
                "status_code": status,
                "body": {"error": error_str[:200]},
                "raw_body": error_str[:500],
                "response_time_ms": 0,
                "transport": "grpc"
            }
