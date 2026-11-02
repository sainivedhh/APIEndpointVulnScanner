"""
analyzer.py - Response Analysis and Vulnerability Detection

Compares mutated request responses against baseline to detect
authentication bypass and privilege escalation vulnerabilities.
Implements low false-positive detection requiring privilege escalation proof.
"""

import json
import re
from typing import Dict, Any, Optional, List

from rich.console import Console

console = Console()

# HTTP status code categories
SUCCESS_CODES = {200, 201, 202, 203, 204, 206}
AUTH_FAILURE_CODES = {401, 403}
CLIENT_ERROR_CODES = {400, 404, 405, 406, 410, 422, 429}
SERVER_ERROR_CODES = {500, 502, 503, 504}

# Keywords indicating admin/privileged content in response
ADMIN_CONTENT_PATTERNS = [
    r'"role"\s*:\s*"admin"',
    r'"isAdmin"\s*:\s*true',
    r'"is_admin"\s*:\s*true',
    r'"admin"\s*:\s*true',
    r'"access"\s*:\s*"full"',
    r'"permissions"\s*:',
    r'"user_list"\s*:',
    r'"users"\s*:\s*\[',
    r'"admin_panel"',
    r'"dashboard"',
    r'"system"',
    r'"management"',
    r'"config"',
]

# Patterns indicating the request was accepted (auth bypassed)
BYPASS_INDICATORS = [
    r'"success"\s*:\s*true',
    r'"authenticated"\s*:\s*true',
    r'"authorized"\s*:\s*true',
    r'"token"\s*:',
    r'"access_token"\s*:',
    r'"data"\s*:',
    r'"result"\s*:',
]

# Patterns indicating the request was REJECTED (not a bypass)
REJECTION_PATTERNS = [
    r'"error"\s*:\s*"[Uu]nauthorized"',
    r'"error"\s*:\s*"[Ff]orbidden"',
    r'"message"\s*:\s*"[Ii]nvalid [Tt]oken"',
    r'"message"\s*:\s*"[Ee]xpired"',
    r'"message"\s*:\s*"[Uu]nauthorized"',
    r'"status"\s*:\s*"[Ff]ailed"',
    r'"code"\s*:\s*401',
    r'"code"\s*:\s*403',
]

SEVERITY_MAP = {
    "Algorithm Substitution": "CRITICAL",
    "Payload Tampering": "CRITICAL",
    "Replay": "HIGH",
    "Expiration Manipulation": "HIGH",
    "HMAC-Specific": "HIGH",
    "Signature Manipulation": "CRITICAL",
}


class ResponseAnalyzer:
    """
    Analyzes HTTP responses to determine if a mutation resulted in a vulnerability.

    Low false-positive strategy:
    1. Status code improvement: 401/403 → 2xx
    2. Response body similarity analysis (did we get different data?)
    3. Privilege escalation indicators in response body
    4. Content-length / body-length difference thresholds
    """

    def __init__(self, verbose: bool = False, fp_threshold: float = 0.8):
        """
        Initialize the analyzer.

        Args:
            verbose: Enable verbose output
            fp_threshold: False positive suppression threshold (0.0-1.0)
        """
        self.verbose = verbose
        self.fp_threshold = fp_threshold

    def analyze(
        self,
        mutation: Dict[str, Any],
        response: Dict[str, Any],
        baseline: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Analyze a mutated response against the baseline.

        Args:
            mutation: Mutation metadata dict
            response: HTTP response from mutated request
            baseline: HTTP response from original valid request

        Returns:
            Finding dictionary with vulnerability verdict and details
        """
        # Guard: timeout responses produce no meaningful signal
        if response.get("status_code", 0) == 0:
            return {
                "mutation_name": mutation.get("name", "Unknown"),
                "category": mutation.get("category", "Unknown"),
                "is_vulnerable": False,
                "confidence": 0.0,
                "severity": "INFO",
                "evidence": ["Request timed out — no response to analyze"],
                "description": mutation.get("description", ""),
                "mutation_detail": mutation.get("mutation_detail", {}),
                "baseline_status": baseline.get("status_code", 0),
                "response_status": 0,
                "response_body_preview": "",
                "response_time_ms": response.get("response_time_ms", 0),
                "response_size_bytes": 0,
                "baseline_size_bytes": len(baseline.get("raw_body", "")),
            }

        is_vulnerable = False
        confidence = 0.0
        evidence = []
        severity = mutation.get("severity_hint", "MEDIUM")

        baseline_code = baseline.get("status_code", 200)
        mutated_code = response.get("status_code", 0)
        baseline_body = json.dumps(baseline.get("body", {}))
        mutated_body = json.dumps(response.get("body", {}))
        baseline_len = len(baseline.get("raw_body", ""))
        mutated_len = len(response.get("raw_body", ""))

        # ── Primary detection: Auth bypass (denial → success) ────────────────
        if baseline_code in AUTH_FAILURE_CODES and mutated_code in SUCCESS_CODES:
            is_vulnerable = True
            confidence = 0.95
            evidence.append(f"Auth bypass: baseline={baseline_code} → mutated={mutated_code}")
            severity = "CRITICAL"

        # ── Secondary: Access granted to new resource ────────────────────────
        elif mutated_code in SUCCESS_CODES:
            # Check if baseline also succeeded — then verify content differs
            if baseline_code in SUCCESS_CODES:
                # Both requests were already authorized. A changed body is not
                # proof of a bypass: require a new privilege indicator absent
                # from the original baseline response.
                escalation_score = self._check_escalation_signals(mutated_body, mutation)
                baseline_escalation = self._check_escalation_signals(baseline_body, mutation)
                if escalation_score > 0.5 and baseline_escalation <= 0.5:
                    is_vulnerable = True
                    confidence = escalation_score
                    evidence.append(
                        f"New privilege indicators in response (score={escalation_score:.2f})"
                    )
                    severity = mutation.get("severity_hint", "HIGH")
            else:
                # Baseline failed, mutation succeeded — bypass confirmed
                is_vulnerable = True
                confidence = 0.90
                evidence.append(f"Access granted by mutation: {mutated_code} (baseline was {baseline_code})")
                severity = mutation.get("severity_hint", "HIGH")

        # ── Tertiary: 5xx on specific mutations may indicate processing ───────
        elif mutated_code in SERVER_ERROR_CODES:
            category = mutation.get("category", "")
            if category in ("Algorithm Substitution", "Signature Manipulation"):
                is_vulnerable = False  # 500 could mean server crashed on bad crypto
                evidence.append(f"Server error {mutated_code} — may indicate invalid token handling")

        # ── Rejection patterns in body (reduce FP) ───────────────────────────
        raw_mutated = response.get("raw_body", "")
        if is_vulnerable and (self._has_rejection_pattern(mutated_body) or
                              self._has_rejection_pattern(raw_mutated)):
            is_vulnerable = False
            confidence = 0.0
            evidence.append("Response contains rejection pattern — marking as not vulnerable (FP reduction)")

        # ── Admin content bonus confidence ───────────────────────────────────
        if is_vulnerable and self._has_admin_content(mutated_body):
            confidence = min(1.0, confidence + 0.1)
            evidence.append("Admin-level content detected in response")

        # Override severity based on category
        if is_vulnerable:
            category = mutation.get("category", "")
            severity = SEVERITY_MAP.get(category, severity)

        finding = {
            "mutation_name": mutation.get("name", "Unknown"),
            "category": mutation.get("category", "Unknown"),
            "is_vulnerable": is_vulnerable,
            "confidence": round(confidence, 3),
            "severity": severity if is_vulnerable else "INFO",
            "evidence": evidence,
            "description": mutation.get("description", ""),
            "mutation_detail": mutation.get("mutation_detail", {}),
            "baseline_status": baseline_code,
            "response_status": mutated_code,
            "response_body_preview": response.get("raw_body", "")[:500],
            "response_time_ms": response.get("response_time_ms", 0),
            "response_size_bytes": mutated_len,
            "baseline_size_bytes": baseline_len,
        }

        if self.verbose and is_vulnerable:
            console.print(f"[red]  ⚠ FINDING: {mutation['name']} | "
                          f"Confidence: {confidence:.0%} | Severity: {severity}[/red]")

        return finding

    def _check_escalation_signals(self, body: str, mutation: Dict[str, Any]) -> float:
        """
        Check for privilege escalation signals in response body.

        Returns confidence score 0.0-1.0.
        """
        score = 0.0
        body_lower = body.lower()

        # Check for admin content patterns
        for pattern in ADMIN_CONTENT_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                score += 0.15

        # Check for bypass indicators
        for pattern in BYPASS_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                score += 0.08

        # Category-specific checks
        category = mutation.get("category", "")
        mutation_detail = mutation.get("mutation_detail", {})

        if category == "Payload Tampering":
            field = mutation_detail.get("field", "")
            if field and field in body_lower:
                score += 0.2  # Field was actually reflected

        # Check if "admin" appears in response
        if "admin" in body_lower:
            score += 0.1

        return min(score, 1.0)

    def _has_rejection_pattern(self, body: str) -> bool:
        """Check if response body contains clear rejection patterns."""
        for pattern in REJECTION_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False

    def _has_admin_content(self, body: str) -> bool:
        """Check if response body contains admin-level content."""
        for pattern in ADMIN_CONTENT_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False

    def compute_response_diff(
        self,
        baseline: Dict[str, Any],
        response: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Compute a diff between baseline and mutated responses.

        Args:
            baseline: Baseline response dict
            response: Mutated response dict

        Returns:
            Diff summary dictionary
        """
        return {
            "status_code_changed": baseline.get("status_code") != response.get("status_code"),
            "baseline_status": baseline.get("status_code"),
            "mutated_status": response.get("status_code"),
            "body_size_diff": (
                len(response.get("raw_body", "")) - len(baseline.get("raw_body", ""))
            ),
            "response_time_diff_ms": (
                response.get("response_time_ms", 0) - baseline.get("response_time_ms", 0)
            ),
            "headers_added": list(
                set(response.get("headers", {}).keys()) -
                set(baseline.get("headers", {}).keys())
            ),
            "headers_removed": list(
                set(baseline.get("headers", {}).keys()) -
                set(response.get("headers", {}).keys())
            ),
        }


    def detect_timing_oracle(
        self,
        mutations: list,
        responses: list,
        baseline_time_ms: float,
        threshold_multiplier: float = 2.5,
    ) -> list:
        """
        Detect timing oracle vulnerabilities.

        A timing oracle occurs when the server takes significantly longer
        to respond to certain mutations — indicating it is actually processing
        (not fast-rejecting) the token. This leaks cryptographic information
        even when the final HTTP response is still 401/403.

        Args:
            mutations:             List of mutation dicts
            responses:             Corresponding response dicts
            baseline_time_ms:      Baseline response time in milliseconds
            threshold_multiplier:  How many times slower triggers a finding

        Returns:
            List of timing oracle finding dicts
        """
        findings = []
        if baseline_time_ms <= 0:
            return findings

        threshold = baseline_time_ms * threshold_multiplier

        for mutation, response in zip(mutations, responses):
            if not response:
                continue
            rt = response.get("response_time_ms", 0)
            if rt > threshold and rt > 200:
                slowdown = rt / baseline_time_ms
                findings.append({
                    "mutation_name": mutation.get("name", "unknown"),
                    "category": "Timing Oracle",
                    "severity": "MEDIUM",
                    "is_vulnerable": True,
                    "confidence": round(min(0.6 + slowdown * 0.04, 0.85), 3),
                    "baseline_status": response.get("status_code", 0),
                    "response_status": response.get("status_code", 0),
                    "baseline_time_ms": round(baseline_time_ms, 1),
                    "response_time_ms": round(rt, 1),
                    "response_size_bytes": len(response.get("raw_body", "")),
                    "baseline_size_bytes": 0,
                    "slowdown_factor": round(slowdown, 2),
                    "description": (
                        f"Response was {slowdown:.1f}x slower than baseline "
                        f"({rt:.0f}ms vs {baseline_time_ms:.0f}ms). Server may be "
                        f"processing this token rather than fast-rejecting it."
                    ),
                    "evidence": [
                        f"Response time: {rt:.0f}ms (baseline: {baseline_time_ms:.0f}ms)",
                        f"Slowdown factor: {slowdown:.1f}x",
                        f"Threshold: {threshold:.0f}ms ({threshold_multiplier}x baseline)",
                    ],
                    "mutation_detail": mutation.get("mutation_detail", {}),
                    "response_body_preview": response.get("raw_body", "")[:200],
                })

        return findings

    def batch_analyze(
        self,
        mutations: List[Dict],
        responses: List[Dict],
        baseline: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Analyze a batch of mutations and responses.

        Args:
            mutations: List of mutation dicts
            responses: List of response dicts (parallel to mutations)
            baseline: Baseline response

        Returns:
            List of finding dicts (only vulnerabilities)
        """
        findings = []
        for mutation, response in zip(mutations, responses):
            if response:
                finding = self.analyze(mutation, response, baseline)
                if finding["is_vulnerable"]:
                    findings.append(finding)
        return findings
