"""
tests/test_scanner.py - Pytest Test Suite for API Scanner v2.0

Tests cover:
- JWT mutation generation and correctness
- HMAC mutation generation
- OAuth mutation generation
- Session / API key / Basic auth mutation generation
- Response analysis and vulnerability detection
- False positive prevention
- Timing oracle detection
- Token health validator
- Config loader
- Reporting functionality
- ML ranker
- Integration / benchmark tests
"""

import json
import time
import base64
import hashlib
import hmac as hmac_lib
import pytest

VALID_JWT_SECRET = "jwt_strong_secret_32bytes!"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _make_valid_jwt(sub="user123", role="user", exp_offset=3600) -> str:
    header  = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": sub, "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + exp_offset,
        "jti": "test-jti-12345",
        "email_verified": role == "admin",
    }
    h   = _b64url_encode(json.dumps(header,  separators=(",", ":")).encode())
    p   = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac_lib.new(VALID_JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _make_oauth_jwt() -> str:
    header  = {"alg": "HS256", "typ": "at+JWT"}
    payload = {
        "sub": "user123", "iss": "https://auth.myapp.com",
        "aud": "https://api.myapp.com",
        "scope": "read:data write:data", "scp": "read:data",
        "client_id": "webapp_client", "azp": "webapp_client",
        "iat": int(time.time()), "exp": int(time.time()) + 3600,
    }
    h   = _b64url_encode(json.dumps(header,  separators=(",", ":")).encode())
    p   = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac_lib.new(VALID_JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _make_valid_hmac_token(message_data=None, secret="secret") -> str:
    msg_data = message_data or {"user_id": "user123", "role": "user", "timestamp": int(time.time())}
    message  = json.dumps(msg_data, separators=(",", ":"))
    sig      = hmac_lib.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    return f"{message}.{_b64url_encode(sig)}"


@pytest.fixture
def valid_jwt():
    return _make_valid_jwt()

@pytest.fixture
def admin_jwt():
    return _make_valid_jwt(sub="admin", role="admin")

@pytest.fixture
def valid_hmac():
    return _make_valid_hmac_token()

@pytest.fixture
def oauth_token():
    return _make_oauth_jwt()


class TestJWTMutator:
    def test_init_parses_valid_jwt(self, valid_jwt):
        from modules.mutator import JWTMutator
        m = JWTMutator(valid_jwt)
        assert m.header["alg"] == "HS256"
        assert m.payload["sub"] == "user123"

    def test_init_rejects_invalid_jwt(self):
        from modules.mutator import JWTMutator
        with pytest.raises(ValueError):
            JWTMutator("not.a.valid.jwt.at.all.extra")

    def test_mut_alg_none_produces_unsigned_token(self, valid_jwt):
        from modules.mutator import JWTMutator
        mutation = JWTMutator(valid_jwt).mut_alg_none()
        parts    = mutation["token"].split(".")
        assert parts[2] == ""
        assert json.loads(_b64url_decode(parts[0]))["alg"] == "none"

    def test_mut_alg_none_uppercase_variants(self, valid_jwt):
        from modules.mutator import JWTMutator
        variants = JWTMutator(valid_jwt).mut_alg_none_uppercase()
        assert len(variants) == 4
        algs = {v["mutation_detail"]["variant"] for v in variants}
        assert "NONE" in algs and "None" in algs

    def test_mut_escalate_role_changes_role(self, valid_jwt):
        from modules.mutator import JWTMutator
        mutations = JWTMutator(valid_jwt).mut_escalate_role()
        assert len(mutations) > 0
        for m in mutations:
            payload = json.loads(_b64url_decode(m["token"].split(".")[1]))
            admin_set = {"admin","superadmin","root","administrator", "admin:all", "read:admin write:admin", "*", "admins", "staff", "full"}
            # Check all fields that mutator might change
            role_fields = ["role", "roles", "user_type", "type", "scope", "permissions", "group", "access", "level"]
            has_admin = any(str(payload.get(f)).lower() in {str(a).lower() for a in admin_set} for f in role_fields)
            has_flag  = any(payload.get(f) is True for f in ["is_admin","admin","superuser","isAdmin", "is_staff", "privileged"])
            assert has_admin or has_flag

    def test_mut_exp_past_sets_exp_to_1(self, valid_jwt):
        from modules.mutator import JWTMutator
        mutation = JWTMutator(valid_jwt).mut_exp_past()
        payload  = json.loads(_b64url_decode(mutation["token"].split(".")[1]))
        assert payload["exp"] == 1

    def test_mut_exp_removed_has_no_exp(self, valid_jwt):
        from modules.mutator import JWTMutator
        mutation = JWTMutator(valid_jwt).mut_exp_removed()
        payload  = json.loads(_b64url_decode(mutation["token"].split(".")[1]))
        assert "exp" not in payload

    def test_mut_empty_signature(self, valid_jwt):
        from modules.mutator import JWTMutator
        assert JWTMutator(valid_jwt).mut_empty_signature()["token"].split(".")[2] == ""

    def test_mut_kid_injection_returns_5(self, valid_jwt):
        from modules.mutator import JWTMutator
        mutations = JWTMutator(valid_jwt).mut_kid_injection()
        assert len(mutations) == 5
        for m in mutations:
            assert "kid" in json.loads(_b64url_decode(m["token"].split(".")[0]))

    def test_generate_all_count_and_fields(self, valid_jwt):
        from modules.mutator import JWTMutator
        mutations = JWTMutator(valid_jwt).generate_all_mutations()
        assert len(mutations) >= 20
        for m in mutations:
            assert all(k in m for k in ["name","token","category","severity_hint"])

    def test_all_mutations_have_valid_token_format(self, valid_jwt):
        from modules.mutator import JWTMutator
        for m in JWTMutator(valid_jwt).generate_all_mutations():
            assert isinstance(m["token"], str) and len(m["token"]) > 10


class TestHMACMutator:
    def test_init_parses_token(self, valid_hmac):
        from modules.mutator import HMACMutator
        m = HMACMutator(valid_hmac, secret="secret")
        assert m.message != "" and m.signature != b""

    def test_weak_secret_guess_generates_multiple(self, valid_hmac):
        from modules.mutator import HMACMutator
        mutations = HMACMutator(valid_hmac).mut_weak_secret_guess()
        assert len(mutations) >= 10
        assert all(m["category"] == "HMAC-Specific" for m in mutations)

    def test_signature_stripped(self, valid_hmac):
        from modules.mutator import HMACMutator
        m = HMACMutator(valid_hmac)
        mutation = m.mut_signature_stripped()
        assert mutation["token"] == m.message

    def test_signature_truncated_lengths(self, valid_hmac):
        from modules.mutator import HMACMutator
        lengths = [m["mutation_detail"]["truncation_length"]
                   for m in HMACMutator(valid_hmac).mut_signature_truncated()]
        assert 4 in lengths and 8 in lengths

    def test_algorithm_downgrade_with_known_secret(self, valid_hmac):
        from modules.mutator import HMACMutator
        algos = {m["mutation_detail"]["algorithm"]
                 for m in HMACMutator(valid_hmac, secret="secret").mut_algorithm_downgrade()}
        assert "sha1" in algos and "md5" in algos

    def test_generate_all_returns_mutations(self, valid_hmac):
        from modules.mutator import HMACMutator
        assert len(HMACMutator(valid_hmac, secret="secret").generate_all_mutations()) >= 15


class TestOAuthMutator:
    def test_scope_escalation_generates_mutations(self, oauth_token):
        from extensions.oauth_mutator import OAuthMutator
        mutations = OAuthMutator(oauth_token).mut_scope_escalation()
        assert len(mutations) >= 3
        assert all(m["category"] == "OAuth-Specific" for m in mutations)

    def test_audience_confusion_includes_wildcard(self, oauth_token):
        from extensions.oauth_mutator import OAuthMutator
        auds = [m["mutation_detail"]["new_aud"]
                for m in OAuthMutator(oauth_token).mut_audience_confusion()]
        assert "*" in auds

    def test_issuer_substitution_excludes_original(self, oauth_token):
        from extensions.oauth_mutator import OAuthMutator
        for m in OAuthMutator(oauth_token).mut_issuer_substitution():
            assert m["mutation_detail"]["new_iss"] != "https://auth.myapp.com"

    def test_generate_all_returns_many(self, oauth_token):
        from extensions.oauth_mutator import OAuthMutator
        mutations = OAuthMutator(oauth_token).generate_all_mutations()
        assert len(mutations) >= 10

    def test_all_forged_tokens_are_unsigned(self, oauth_token):
        from extensions.oauth_mutator import OAuthMutator
        for m in OAuthMutator(oauth_token).generate_all_mutations():
            assert m["token"].endswith(".")

    def test_invalid_token_raises(self):
        from extensions.oauth_mutator import OAuthMutator
        with pytest.raises(ValueError):
            OAuthMutator("notavalidtoken")


class TestSessionCookieMutator:
    def test_null_session_mutation(self):
        from modules.generic_auth_scanner import SessionCookieMutator
        m = SessionCookieMutator("sessionid", "abc123").mut_null_session()
        assert m["token"] == "" and m["category"] == "Session-Cookie"

    def test_admin_guess_returns_list(self):
        from modules.generic_auth_scanner import SessionCookieMutator
        mutations = SessionCookieMutator("sessionid", "abc123").mut_admin_session_guess()
        assert len(mutations) >= 5

    def test_integer_walk_on_numeric_session(self):
        from modules.generic_auth_scanner import SessionCookieMutator
        mutations = SessionCookieMutator("sessionid", "1000").mut_integer_id_walk()
        tokens = [int(m["token"]) for m in mutations]
        assert 1001 in tokens and 999 in tokens

    def test_integer_walk_skipped_for_non_numeric(self):
        from modules.generic_auth_scanner import SessionCookieMutator
        assert SessionCookieMutator("sessionid", "abcxyz").mut_integer_id_walk() == []

    def test_generate_all_returns_mutations(self):
        from modules.generic_auth_scanner import SessionCookieMutator
        assert len(SessionCookieMutator("sessionid", "user_session_ab12").generate_all_mutations()) >= 10


class TestAPIKeyMutator:
    def test_no_key_mutation(self):
        from modules.generic_auth_scanner import APIKeyMutator
        m = APIKeyMutator("mykey123").mut_no_key()
        assert m["token"] == "" and m["severity_hint"] == "CRITICAL"

    def test_common_keys_includes_test(self):
        from modules.generic_auth_scanner import APIKeyMutator
        tokens = [m["token"] for m in APIKeyMutator("mykey123").mut_common_keys()]
        assert "test" in tokens and "admin" in tokens

    def test_env_swap_live_to_test(self):
        from modules.generic_auth_scanner import APIKeyMutator
        tokens = [m["token"] for m in APIKeyMutator("sk_live_abc123").mut_env_swap()]
        assert "sk_test_abc123" in tokens

    def test_strip_prefix_sk_live(self):
        from modules.generic_auth_scanner import APIKeyMutator
        tokens = [m["token"] for m in APIKeyMutator("sk_live_abc123").mut_strip_prefix()]
        assert "abc123" in tokens

    def test_generate_all_returns_mutations(self):
        from modules.generic_auth_scanner import APIKeyMutator
        assert len(APIKeyMutator("sk_live_abc123").generate_all_mutations()) >= 15


class TestBasicAuthMutator:
    def test_default_credentials_contains_admin(self):
        from modules.generic_auth_scanner import BasicAuthMutator
        names = [m["mutation_detail"]["username"]
                 for m in BasicAuthMutator("alice", "secret123").mut_default_credentials()]
        assert "admin" in names

    def test_null_password_mutation(self):
        from modules.generic_auth_scanner import BasicAuthMutator
        m = BasicAuthMutator("alice", "secret123").mut_null_password()
        assert m["mutation_detail"]["username"] == "alice"
        assert m["token"].startswith("Basic ")

    def test_tokens_are_base64_encoded(self):
        from modules.generic_auth_scanner import BasicAuthMutator
        for m in BasicAuthMutator("alice", "secret").mut_default_credentials():
            assert m["token"].startswith("Basic ")
            assert ":" in base64.b64decode(m["token"][6:]).decode()

    def test_generate_all_returns_mutations(self):
        from modules.generic_auth_scanner import BasicAuthMutator
        assert len(BasicAuthMutator("admin", "password").generate_all_mutations()) >= 10


class TestTokenValidator:
    def test_healthy_jwt_passes(self):
        from modules.token_validator import validate_token_health
        ok, msg = validate_token_health(_make_valid_jwt(exp_offset=3600), "jwt")
        assert ok is True and "WARNING" not in msg

    def test_expired_jwt_fails(self):
        from modules.token_validator import validate_token_health
        ok, msg = validate_token_health(_make_valid_jwt(exp_offset=-100), "jwt")
        assert ok is False and "EXPIRED" in msg

    def test_near_expiry_warns(self):
        from modules.token_validator import validate_token_health
        ok, msg = validate_token_health(_make_valid_jwt(exp_offset=60), "jwt")
        assert ok is True and "WARNING" in msg

    def test_hmac_token_passes(self):
        from modules.token_validator import validate_token_health
        ok, _ = validate_token_health(_make_valid_hmac_token(), "hmac")
        assert ok is True

    def test_short_hmac_fails(self):
        from modules.token_validator import validate_token_health
        ok, _ = validate_token_health("abc", "hmac")
        assert ok is False

    def test_malformed_jwt_fails(self):
        from modules.token_validator import validate_token_health
        ok, _ = validate_token_health("not.a.valid.jwt.extra", "jwt")
        assert ok is False

    def test_basic_requires_colon(self):
        from modules.token_validator import validate_token_health
        assert validate_token_health("nocolon", "basic")[0] is False
        assert validate_token_health("user:pass", "basic")[0] is True

    def test_summarise_jwt_extracts_claims(self):
        from modules.token_validator import summarise_token
        s = summarise_token(_make_valid_jwt(sub="alice", role="user"), "jwt")
        assert s["sub"] == "alice" and s["alg"] == "HS256" and s["has_jti"] is True

    def test_summarise_hmac(self):
        from modules.token_validator import summarise_token
        s = summarise_token(_make_valid_hmac_token(), "hmac")
        assert s["type"] == "hmac" and "preview" in s


class TestResponseAnalyzer:
    @pytest.fixture
    def analyzer(self):
        from modules.analyzer import ResponseAnalyzer
        return ResponseAnalyzer(verbose=False)

    @pytest.fixture
    def baseline_403(self):
        return {"status_code": 403, "body": {}, "raw_body": '{"error":"Forbidden"}',
                "response_time_ms": 30}

    @pytest.fixture
    def baseline_200(self):
        return {"status_code": 200, "body": {"role": "user"}, "raw_body": '{"role":"user"}',
                "response_time_ms": 50}

    def _mutation(self, name="alg:none", category="Algorithm Substitution", sev="CRITICAL"):
        return {"name": name, "category": category, "severity_hint": sev,
                "description": "test", "mutation_detail": {}}

    def test_auth_bypass_detected(self, analyzer, baseline_403):
        response = {"status_code": 200, "body": {}, "raw_body": '{"data":"secret"}',
                    "response_time_ms": 45}
        f = analyzer.analyze(self._mutation(), response, baseline_403)
        assert f["is_vulnerable"] is True and f["confidence"] >= 0.9

    def test_rejection_response_not_flagged(self, analyzer, baseline_403):
        response = {"status_code": 403, "body": {}, "raw_body": '{"error":"Unauthorized"}',
                    "response_time_ms": 30}
        assert analyzer.analyze(self._mutation(), response, baseline_403)["is_vulnerable"] is False

    def test_rejection_body_prevents_fp(self, analyzer, baseline_200):
        response = {"status_code": 200, "body": {},
                    "raw_body": '{"message":"Invalid token","code":401}',
                    "response_time_ms": 30}
        assert analyzer.analyze(self._mutation(), response, baseline_200)["is_vulnerable"] is False

    def test_timeout_response_not_flagged(self, analyzer, baseline_403):
        response = {"status_code": 0, "error": "timeout", "body": None,
                    "raw_body": "", "response_time_ms": 10000}
        assert analyzer.analyze(self._mutation(), response, baseline_403)["is_vulnerable"] is False

    def test_500_not_flagged(self, analyzer, baseline_403):
        response = {"status_code": 500, "body": {}, "raw_body": '{"error":"Internal"}',
                    "response_time_ms": 5}
        assert analyzer.analyze(self._mutation(), response, baseline_403)["is_vulnerable"] is False

    def test_compute_response_diff(self, analyzer, baseline_200):
        response = {"status_code": 403, "body": {}, "raw_body": "",
                    "response_time_ms": 30,
                    "headers": {"Content-Type": "application/json", "X-New": "yes"}}
        baseline_with_h = {**baseline_200, "headers": {"Content-Type": "application/json"}}
        diff = analyzer.compute_response_diff(baseline_with_h, response)
        assert diff["status_code_changed"] is True and "X-New" in diff["headers_added"]

    def test_batch_analyze_filters_non_vulnerable(self, analyzer, baseline_403):
        mutations = [self._mutation("vuln"), self._mutation("safe","Replay","LOW")]
        responses = [
            {"status_code": 200, "body": {}, "raw_body": '{"is_admin":true}', "response_time_ms": 30},
            {"status_code": 403, "body": {}, "raw_body": '{"error":"Forbidden"}', "response_time_ms": 20},
        ]
        findings = analyzer.batch_analyze(mutations, responses, baseline_403)
        assert len(findings) == 1 and findings[0]["mutation_name"] == "vuln"


class TestTimingOracle:
    @pytest.fixture
    def analyzer(self):
        from modules.analyzer import ResponseAnalyzer
        return ResponseAnalyzer()

    def test_slow_response_flagged(self, analyzer):
        mutations = [{"name": "t", "category": "HMAC-Specific", "severity_hint": "HIGH", "mutation_detail": {}}]
        responses = [{"status_code": 401, "raw_body": "", "response_time_ms": 800}]
        findings  = analyzer.detect_timing_oracle(mutations, responses, baseline_time_ms=100)
        assert len(findings) == 1 and findings[0]["category"] == "Timing Oracle"

    def test_fast_response_not_flagged(self, analyzer):
        mutations = [{"name": "t", "category": "JWT", "severity_hint": "HIGH", "mutation_detail": {}}]
        responses = [{"status_code": 401, "raw_body": "", "response_time_ms": 110}]
        assert analyzer.detect_timing_oracle(mutations, responses, baseline_time_ms=100) == []

    def test_none_response_skipped(self, analyzer):
        mutations = [{"name": "t", "category": "JWT", "severity_hint": "HIGH", "mutation_detail": {}}]
        assert analyzer.detect_timing_oracle(mutations, [None], baseline_time_ms=100) == []


class TestReporter:
    def test_save_json(self, tmp_path):
        from modules.reporter import Reporter
        data = {
            "scan_info": {"target": "http://t.com", "token_type": "jwt", "timestamp": "2024",
                          "total_mutations": 10, "baseline_status": 403},
            "findings": [],
            "summary": {"total_vulnerabilities": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        }
        path = str(tmp_path / "r.json")
        Reporter().save_json(data, path)
        with open(path, encoding="utf-8") as f:
            assert json.load(f)["scan_info"]["target"] == "http://t.com"

    def test_save_html(self, tmp_path):
        from modules.reporter import Reporter
        data = {
            "scan_info": {"target": "http://t.com", "token_type": "jwt", "timestamp": "2024",
                          "total_mutations": 10, "baseline_status": 403},
            "findings": [{"mutation_name": "alg:none", "category": "Algorithm Substitution",
                          "severity": "CRITICAL", "is_vulnerable": True, "confidence": 0.95,
                          "evidence": ["bypass"], "description": "Test", "mutation_detail": {},
                          "baseline_status": 403, "response_status": 200,
                          "response_body_preview": "{}", "response_time_ms": 45,
                          "response_size_bytes": 50, "baseline_size_bytes": 30}],
            "summary": {"total_vulnerabilities": 1, "critical": 1, "high": 0, "medium": 0, "low": 0},
        }
        path = str(tmp_path / "r.html")
        Reporter().save_html(data, path)
        with open(path, encoding="utf-8") as f:
            html = f.read()
        assert "alg:none" in html and "CRITICAL" in html


class TestConfigLoader:
    def test_load_valid_yaml(self, tmp_path):
        from modules.config_loader import load_config
        cfg = tmp_path / "c.yaml"
        cfg.write_text("target: http://localhost:5000\nendpoint: /api\ntype: jwt\n")
        loaded = load_config(str(cfg))
        assert loaded["target"] == "http://localhost:5000"

    def test_missing_file_raises(self):
        from modules.config_loader import load_config
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/config.yaml")

    def test_invalid_yaml_raises(self, tmp_path):
        from modules.config_loader import load_config
        cfg = tmp_path / "bad.yaml"
        cfg.write_text("key: [unclosed\n")
        with pytest.raises(ValueError):
            load_config(str(cfg))

    def test_merge_cli_overrides_config(self):
        from modules.config_loader import merge_config_with_args
        merged = merge_config_with_args(
            {"target": "http://config", "endpoint": "/api", "verbose": False},
            {"target": "http://cli", "verbose": True, "output": None},
        )
        assert merged["target"] == "http://cli"
        assert merged["endpoint"] == "/api"
        assert merged["verbose"] is True


class TestMLRanker:
    def test_scoring_is_deterministic(self):
        from extensions.ml_ranker import MLRanker
        m = {"name": "alg:none bypass", "category": "Algorithm Substitution",
             "severity_hint": "CRITICAL", "mutation_detail": {}}
        r = MLRanker()
        assert r.score(m) == r.score(m)

    def test_high_priority_ranked_first(self):
        from extensions.ml_ranker import MLRanker
        mutations = [
            {"name": "nbf future", "category": "Expiration Manipulation",
             "severity_hint": "LOW", "mutation_detail": {}},
            {"name": "alg:none bypass", "category": "Algorithm Substitution",
             "severity_hint": "CRITICAL", "mutation_detail": {}},
        ]
        assert MLRanker().rank_mutations(mutations)[0]["name"] == "alg:none bypass"

    def test_rank_preserves_all(self):
        from extensions.ml_ranker import MLRanker
        muts = [{"name": f"m{i}", "category": "Replay", "severity_hint": "MEDIUM",
                 "mutation_detail": {}} for i in range(10)]
        assert len(MLRanker().rank_mutations(muts)) == 10

    def test_ml_score_in_range(self):
        from extensions.ml_ranker import MLRanker
        ranked = MLRanker().rank_mutations([
            {"name": "t", "category": "HMAC-Specific", "severity_hint": "HIGH", "mutation_detail": {}}
        ])
        assert 0.0 <= ranked[0]["ml_priority_score"] <= 1.0


class TestBenchmark:
    def test_false_positive_rate_under_threshold(self):
        from modules.analyzer import ResponseAnalyzer
        analyzer = ResponseAnalyzer()
        baseline = {"status_code": 401, "body": {}, "raw_body": '{"error":"Unauthorized"}',
                    "response_time_ms": 20}
        fp = sum(
            1 for i in range(50)
            if analyzer.analyze(
                {"name": f"m{i}", "category": "Algorithm Substitution",
                 "severity_hint": "CRITICAL", "description": "", "mutation_detail": {}},
                {"status_code": 401, "body": {},
                 "raw_body": '{"error":"Unauthorized","message":"Invalid token"}',
                 "response_time_ms": 20},
                baseline,
            )["is_vulnerable"]
        )
        assert fp / 50 < 0.05

    def test_true_positive_rate_for_alg_none(self):
        from modules.analyzer import ResponseAnalyzer
        analyzer = ResponseAnalyzer()
        baseline = {"status_code": 403, "body": {}, "raw_body": '{"error":"Forbidden"}',
                    "response_time_ms": 20}
        mutation = {"name": "alg:none", "category": "Algorithm Substitution",
                    "severity_hint": "CRITICAL", "description": "", "mutation_detail": {}}
        response = {"status_code": 200, "body": {}, "raw_body": '{"is_admin":true,"role":"admin"}',
                    "response_time_ms": 45}
        tp = sum(1 for _ in range(10)
                 if analyzer.analyze(mutation, response, baseline)["is_vulnerable"])
        assert tp / 10 >= 0.9
