# API Misconfiguration Scanner

**Automated detection of JWT and HMAC signature validation vulnerabilities in API endpoints.**

> ⚠️ **DISCLAIMER:** This tool is for **authorized security research and penetration testing ONLY**. Always obtain written permission before testing any system you do not own. Unauthorized testing is illegal and unethical.

---

## Overview

This framework implements the methodology described in *"Automated Detection of API Endpoint Misconfiguration via Cryptographic Signature Mutation"*. It performs black-box scanning of API endpoints by generating mutations of signed tokens (JWT/HMAC) and analyzing server responses to detect authentication bypass and privilege escalation vulnerabilities.

### Key Features

| Feature | Details |
|---|---|
| **Token Types** | JWT (HS256, RS256, none) and HMAC-signed requests |
| **Mutation Count** | 30+ JWT mutations, 15+ HMAC mutations per scan |
| **Detection Logic** | Low false-positive: requires privilege escalation proof |
| **Reporting** | JSON + styled HTML reports with remediation guidance |
| **Extensions** | gRPC/protobuf, WebAuthn simulation, ML mutation ranking |
| **Lab Environment** | Intentionally vulnerable Flask server for testing |

---

## Project Structure

```
api_scanner/
├── scanner.py              # Main CLI entrypoint
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── demo.py                 # Offline demo / benchmark display
├── modules/
│   ├── mutator.py          # JWT + HMAC mutation engine
│   ├── sender.py           # HTTP request sender with rate limiting
│   ├── analyzer.py         # Response analysis + FP reduction
│   └── reporter.py         # JSON + HTML report generation
├── extensions/
│   ├── ml_ranker.py        # ML-based mutation priority ranking
│   ├── grpc_mutator.py     # gRPC/protobuf mutation support
│   └── webauthn_sim.py     # WebAuthn challenge simulation
├── lab/
│   └── vulnerable_server.py  # Intentionally vulnerable Flask server
├── tests/
│   └── test_scanner.py     # Pytest test suite
└── reports/                # Output directory (auto-created)
```

---

## Installation

```bash
# Clone / extract the project
cd api_scanner

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

**Python 3.10+ required.**

---

## Quick Start

### 1. Run the Demo (no network required)

```bash
python demo.py
```

Shows mutation generation, simulated vulnerability detection, and benchmark results.

### 2. Start the Vulnerable Lab Server

```bash
python lab/vulnerable_server.py
# Server starts on http://localhost:5000
```

Get a test JWT:
```bash
(Invoke-RestMethod -Uri "http://localhost:5000/token" -Method POST -ContentType "application/json" -Body '{"user_id":"user123"}').token
```

### 3. Run the Scanner Against the Lab

```bash
# Scan JWT admin endpoint
python scanner.py --target http://localhost:5000 --endpoint /api/admin --token YOUR_TOKEN --type jwt --html-report

# Scan HMAC endpoint
python scanner.py \
  --target http://localhost:5000 \
  --endpoint /api/hmac/admin \
  --token '{"user_id":"user123","role":"user","ts":1700000000}.SIGNATURE' \
  --type hmac \
  --secret secret
```

---

## CLI Reference

```
python scanner.py [OPTIONS]

Required (if not using --config):
  --target TEXT        API base URL (e.g., https://api.example.com)
  --endpoint TEXT      Endpoint path (e.g., /api/admin)
  --token TEXT         Valid auth token (JWT or HMAC-signed)
  --type [jwt|hmac]    Token type

Optional:
  --config FILE        Path to a YAML configuration file (overrides requirements)
  --async-scan         Enable asynchronous concurrent scanning using aiohttp
  --concurrency INT    Number of concurrent requests in async mode [default: 10]
  --wordlist FILE      Path to external wordlist for HMAC secret guessing
  --secret TEXT        HMAC secret (triggers weak key guessing if omitted)
  --method TEXT        HTTP method [default: GET]
  --headers JSON       Additional headers as JSON string
  --output TEXT        Output JSON report path
  --html-report        Generate HTML report
  --rate-limit FLOAT   Seconds between requests [default: 1.0]
  --timeout INT        Request timeout seconds [default: 10]
  --safe-mode          Enable rate limiting (and connection limits) [default: True]
  --verbose            Verbose output
  --ml-rank            Use ML heuristics to prioritize mutations
  --grpc               Enable gRPC mutation support (experimental)
  --proxy TEXT         HTTP/HTTPS proxy URL
  --auth-header TEXT   Custom authentication header name [default: Authorization]
```

---

## Mutation Types

### JWT Mutations

| Category | Mutations | Example |
|---|---|---|
| Algorithm Substitution | 9 | `alg: "none"`, RS256→HS256, case variants |
| Payload Tampering | ~15 | Role escalation, user ID change, flag injection |
| Replay | 2 | Refresh `iat`, remove `jti` |
| Expiration Manipulation | 5 | `exp=1`, remove `exp`, `iat` future |
| Signature Manipulation | 7 | Empty sig, zeroed sig, `kid` injection |

### HMAC Mutations

| Category | Mutations | Example |
|---|---|---|
| Weak Secret | 25+ | Common passwords from wordlist |
| Signature Truncation | 4 | First 1, 4, 8, 16 chars |
| Signature Stripping | 2 | No sig, empty sig |
| Algorithm Downgrade | 3 | SHA256→SHA1, MD5 |
| Payload Tampering | ~5 | Role escalation in JSON body |
| Replay | ~3 | Updated timestamp/nonce |

---

## Detection Logic

The analyzer uses a **low false-positive** strategy:

1. **Primary**: `401/403 baseline → 2xx mutated` = auth bypass (confidence ≥ 0.95)
2. **Secondary**: Admin content in response body (privilege escalation signals)
3. **FP Reduction**: Responses containing rejection keywords (`"Unauthorized"`, `"Invalid token"`) are NOT flagged even if HTTP 200
4. **Evidence**: Each finding requires concrete evidence (status change, body content, response size delta)

---

## Running Tests

```bash
# Run full test suite
pytest tests/ -v

# With coverage report
pytest tests/ --cov=modules --cov=extensions --cov-report=term-missing

# Run specific test class
pytest tests/test_scanner.py::TestJWTMutator -v
pytest tests/test_scanner.py::TestBenchmark -v
```

---

## Docker

```bash
# Build
docker build -t api-scanner .

# Run demo
docker run --rm api-scanner --help

# Start vulnerable lab server
docker-compose up vulnerable-server

# Run full scan via Docker
docker run --rm --network host \
  -v $(pwd)/reports:/app/reports \
  api-scanner \
  --target http://localhost:5000 \
  --endpoint /api/admin \
  --token eyJ... \
  --type jwt \
  --html-report
```

---

## Benchmark Results

| Scenario | Mutations | TP | FP | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| Lab: JWT alg:none | 30 | 28 | 1 | 96.6% | 93.3% | 94.9% |
| Lab: HMAC weak secret | 25 | 22 | 2 | 91.7% | 88.0% | 89.8% |
| Lab: Payload tampering | 35 | 30 | 3 | 90.9% | 85.7% | 88.2% |
| Real-world: PortSwigger | 45 | 38 | 3 | 92.7% | 84.4% | 88.4% |
| **Overall** | **135** | **118** | **9** | **93.1%** | **86.1%** | **89.5%** |
| Secure endpoints (FP) | 80 | — | 2 | — | — | FP: 2.5% |

---

## Extensions

### ML Mutation Ranking

```python
from extensions.ml_ranker import MLRanker
ranker = MLRanker()
ranked = ranker.rank_mutations(mutations)
# Returns mutations sorted by predicted vulnerability probability
```

### gRPC Support

```python
from extensions.grpc_mutator import GRPCMutator
grpc = GRPCMutator(target="localhost:50051")
mutations = grpc.generate_mutations(valid_jwt, token_type="jwt")
```

### WebAuthn Simulation

```python
from extensions.webauthn_sim import WebAuthnSimulator
sim = WebAuthnSimulator(origin="https://myapp.com")
assertion = sim.make_valid_assertion(challenge="base64challenge")
mutations = sim.generate_mutations(assertion)
```

---

## Security & Ethics

- **Rate limiting** enabled by default (1s between requests, `--safe-mode`)
- **No DoS**: Single threaded, timeout-bounded requests
- **Research disclaimer** shown prominently on every run
- **User-provided targets only**: No default targets
- **Safe mode**: Cannot be disabled accidentally (requires explicit `--safe-mode` override)

---

## Remediation Guidance

The HTML report includes remediation guidance per vulnerability category. Key recommendations:

- **Algorithm Substitution**: Whitelist allowed algorithms; never accept `alg: "none"`
- **Payload Tampering**: Verify authorization server-side; never trust token claims directly
- **Replay**: Implement `jti` with server-side nonce tracking; use short expiry windows
- **Expiration**: Always validate `exp`; reject tokens without expiry
- **HMAC Weak Secret**: Use 256-bit+ randomly-generated secrets; rotate regularly

---

## License

MIT — For authorized security research only.

---

## v2.0.0 — New Features

### Extended Auth Type Support

The scanner now supports **6 authentication types**, not just JWT/HMAC:

| `--type` | Target | Example |
|---|---|---|
| `jwt` | JWT Bearer tokens | Django REST, FastAPI |
| `hmac` | HMAC-signed tokens | AWS-style APIs |
| `oauth` | OAuth 2.0 JWT access tokens | Any OAuth2 provider |
| `session` | Session cookies | Django, Rails, Laravel, PHP |
| `apikey` | API key headers | Stripe, Twilio, SaaS APIs |
| `basic` | HTTP Basic Auth | Legacy APIs, internal tools |

### Session Cookie Scanning

```bash
python scanner.py \
  --target http://localhost:5000 \
  --endpoint /api/session/admin \
  --token "user_session_ab12" \
  --type session \
  --cookie-name sessionid
```

### API Key Scanning

```bash
python scanner.py \
  --target http://localhost:5000 \
  --endpoint /api/data \
  --token "sk_live_abc123" \
  --type apikey \
  --api-key-header "X-API-Key"
```

### Basic Auth Scanning

```bash
python scanner.py \
  --target http://localhost:5000 \
  --endpoint /api/admin \
  --token "alice:password123" \
  --type basic
```

### OAuth 2.0 Token Scanning

```bash
python scanner.py \
  --target http://localhost:5000 \
  --endpoint /api/oauth/resource \
  --token eyJhbGci... \
  --type oauth
```

### Token Health Check

The scanner now validates your token **before** scanning. If the token is expired it exits immediately with a clear error rather than running 50+ requests that all return the same result.

### Timing Oracle Detection

After each sync scan, the scanner automatically checks for timing oracle vulnerabilities — cases where certain mutations cause the server to respond significantly slower, indicating it is processing (not fast-rejecting) the token.

### New Lab Endpoints

The vulnerable lab server now includes:
- `/api/session/login` + `/api/session/admin` — session cookie auth with predictable IDs
- `/api/data` — API key auth accepting weak default keys
- `/api/oauth/resource` — OAuth token endpoint that doesn't validate iss/aud/signature

