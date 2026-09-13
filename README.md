# AuthScope

**Login Intelligence & Anti-Bot Detection Platform**

AuthScope takes a login URL as input and returns a complete fingerprint of that login page — who powers the authentication, how secure it is, and what will block automation.

> **Core Principle:** AuthScope only **detects** and **reports**. It never bypasses captchas, evades WAFs, or automates logins. It answers *"what am I up against?"* before you build anything.

---

## Table of Contents

- [What AuthScope Does](#what-authscope-does)
- [Who Is It For](#who-is-it-for)
- [Feature Set](#feature-set)
  - [Detection Engine](#a-detection-engine)
  - [Platform Features](#b-platform-features)
  - [Scoring](#c-scoring)
  - [AI Features Roadmap](#d-ai-features-roadmap)
- [How It Works](#how-it-works)
  - [Architecture](#architecture)
  - [Scan Lifecycle](#scan-lifecycle-data-flow-for-one-scan)
- [Detection Details](#detection-details)
- [Tech Stack](#tech-stack)
- [Database Schema](#database-schema)
- [API Reference](#api-reference)
- [Signature System](#signature-system)
- [Production Considerations](#production-considerations)
- [Project Structure](#project-structure-planned)
- [Roadmap](#roadmap)

---

## What AuthScope Does

Given a login URL, AuthScope launches an isolated, instrumented browser session and answers three questions:

### 1. Who handles auth?

Identifies the authentication provider and flow:

| Providers | Flows |
|---|---|
| Auth0, Firebase Auth, Okta, AWS Cognito, Clerk, Azure AD / Entra ID, OneLogin, Ping Identity, Keycloak, Supabase, WorkOS, custom-built, and **40+ more** | OAuth2 (code/implicit), OIDC, SAML, Password form login, Magic Link, OTP/SMS code, Passkey / WebAuthn |

Detected via **multi-signal correlation**: script URLs, global JS objects (`window.auth0`, `firebase`, etc.), `/.well-known/openid-configuration` network probes, and form action analysis.

### 2. How secure is it?

Audits the security posture of the login page:

- Security headers: `Strict-Transport-Security` (HSTS), `Content-Security-Policy`, `X-Frame-Options`, `Cross-Origin-*` (COOP/CORP), `Permissions-Policy`
- Cookie hygiene: `Secure`, `HttpOnly`, `SameSite` flags on session cookies
- CSRF token presence in forms
- MFA indicators (2FA prompts, WebAuthn registration, TOTP references)
- Password policy hints (client-side validation patterns, strength meters)

Produces a **Risk Score** for security misconfigurations.

### 3. What will block automation?

Maps every anti-bot defense on the page:

| Category | Detected |
|---|---|
| **Captchas** | reCAPTCHA v2 (checkbox/invisible), reCAPTCHA v3 (score-based), hCaptcha, Cloudflare Turnstile, Arkose Labs FunCaptcha, GeeTest |
| **WAF / Bot Protection** | Cloudflare, DataDome, PerimeterX / HUMAN, Akamai Bot Manager, Kasada, Imperva / Incapsula |
| **Browser Fingerprinting** | FingerprintJS / FPJS Pro, Castle, Sift, CreepJS, Akamai sensor SDK, Canvas/WebGL fingerprint collection |
| **Passive defenses** | Honeypot fields, JS challenges, behavioral analytics, cookie tokens (`__cf_bm`, `_abck`, `_pxhd`) |

Produces an **Automation Difficulty Score (0–100)** with plain-English reasoning: *"Very hard — Akamai Bot Manager + invisible Turnstile + DataDome fingerprinting detected."*

Every finding is backed by **evidence**: matched signature signals, raw headers, HAR file, screenshot, and DOM snapshot.

---

## Who Is It For

| User | Use case |
|---|---|
| **Automation teams** | Know if a site is automatable *before* investing weeks building a bot. Get a difficulty score and blocker inventory upfront. |
| **Security teams** | Audit their own or third-party login posture. Track regressions ("did our CSP header disappear?") via historical diffs. |
| **Product teams** | Competitive intel on auth providers. "Which SSO provider does our competitor use? Do they enforce MFA?" |
| **Sales / Solutions engineers** | Pre-flight checks when integrating with customer systems. |
| **Researchers** | Large-scale analysis of auth & anti-bot adoption across the web via bulk scans. |

---

## Feature Set

### A. Detection Engine

#### Auth Provider Detection
- **Multi-signal detection** — correlates four independent signal sources:
  1. Script URL patterns (`cdn.auth0.com`, `www.gstatic.com/firebasejs/...`)
  2. Global JS objects (`window.auth0Client`, `window.firebase`, `window.Clerk`, ...)
  3. Network requests to well-known endpoints (`/.well-known/openid-configuration`, `/.well-known/saml-metadata`)
  4. Form action / input field analysis (`action="/u/login"`, `name="username"` + password field)
- **40+ provider signatures** with versioned evidence — every match records *which* signal fired and *where*
- **Flow detection**: OAuth authorization-code redirect chains, SAML POST bindings, classic password POSTs, magic-link email-first flows, passkey/WebAuthn API calls (`navigator.credentials.get` with `publicKey`)
- Confidence scoring per finding (multiple agreeing signals → higher confidence)

#### Security Audit
- Full response header audit: HSTS (with `max-age`, `includeSubDomains`, `preload`), CSP (directive-level breakdown), XFO, COOP, CORP, COEP, `Permissions-Policy`, referrer policy
- `Set-Cookie` parsing: flags, expiry, domain scope of session/auth cookies
- CSRF token detection: hidden inputs, meta tags, cookie-to-header patterns (double-submit)
- Honeypot field detection (hidden inputs with suspicious names like `bot-field`, off-screen positioning)
- `autocomplete` attribute analysis on credential fields
- Client-side password policy extraction from inline validation rules
- MFA presence heuristics

#### Captcha Detection
- Detects captcha vendor **and version/type**: `recaptcha_v2_checkbox`, `recaptcha_v2_invisible`, `recaptcha_v3_score`, `hcaptcha`, `turnstile_managed`, `turnstile_invisible`, `arkose`, `geetest_v3/v4`
- Reports whether the widget is **visible or invisible**
- Distinguishes **score-based** (v3 — always running) vs **challenge-based** (v2 — triggered on suspicion)
- Captures widget render events and challenge script loads as evidence

#### WAF / Bot Protection Detection
- Response headers (`server: cloudflare`, `x-datadome`, `x-akamai-transformed`, `x-iinfo`, ...)
- Detection cookies (`__cf_bm`, `cf_chl_*`, `_datadome`, `_px*`, `ak_bmsc`, `_abck`, `bm_sv`, `incap_ses_*`, `kpsdk_ct`)
- JavaScript challenge interstitials (Cloudflare "Just a moment...", PerimeterX press-and-hold, Kasada)
- TLS termination fingerprints (JA3/JA4 mismatch patterns between claimed UA and cipher suite behavior)
- Retry logic marks scans as `waf_blocked` when served a 403 challenge instead of the real page

#### Fingerprinting Library Detection
- FingerprintJS (open-source + FPJS Pro bot detection API calls)
- Castle, Sift Science, CreepJS
- Vendor SDKs: Akamai BM telemetry, DataDome device check, PerimeterX collector endpoints
- Generic canvas/WebGL/AudioContext fingerprint read detection

#### Evidence Capture
Per scan, stored to object storage:
- **HAR file** — complete request/response log including timing
- **Screenshot** — full-page PNG at scan completion
- **DOM snapshot** — post-load serialized DOM (PII-stripped)
- **Trace** — Playwright tracing archive for debugging scans
- Raw structured evidence JSON attached to every finding

### B. Platform Features

| Feature | Description |
|---|---|
| **Single scan** | `POST /v1/scans` — async job with webhook or polling delivery |
| **Bulk scan** | `POST /v1/scans/bulk` — CSV upload of up to 1000 URLs, processed as a batch |
| **Historical diff** | "What changed on this login page in the last 30 days?" — provider swaps, new captcha vendors, removed headers, score deltas |
| **Automation Difficulty Score** | 0–100 with itemized reasoning per contributing factor |
| **Risk Score** | Security misconfiguration score based on missing/misconfigured protections |
| **Webhooks & polling** | Async completion callbacks with retry; polling endpoint for simple integrations |
| **Dashboard** | Search, filter, sort scans; interactive evidence viewer (HAR explorer, screenshot viewer, finding inspector) |
| **Public API** | API-key authenticated, 60 req/min default rate limit, JSON responses |
| **Signature Management** | Add/update/disable detection signatures at runtime — no deploy required. YAML in Git → loaded to Postgres → hot-reloaded into workers |
| **Proxy & Identity Pool** | Managed residential proxy pools (per-country routing) and rotating browser identities for scanning hard targets |
| **False-positive feedback loop** | Mark findings as false positives; feeds model retraining and signature tuning |
| **Agent integration (MCP)** | Model Context Protocol server exposing scans as agent tools over stdio / Streamable HTTP / SSE — see [`docs/MCP.md`](docs/MCP.md) |

### C. Scoring

#### Automation Difficulty Score (0–100)
Weighted composite of detected blockers:

| Signal | Weight contribution |
|---|---|
| WAF/bot protection vendor count & tier | highest |
| Invisible / score-based captcha | high |
| Visible captcha | medium-high |
| Fingerprinting libraries present | medium |
| Behavioral analysis / JS challenges | medium |
| Honeypots, CSRF complexity | low-medium |

Returned with **reasoning**: `"Score 87: Akamai Bot Manager (TLS + sensor), invisible Turnstile, FPJS Pro detected."`

> Phase 2 replaces heuristic weights with an XGBoost/LightGBM model trained on historical automation outcomes, with SHAP-based explanations.

#### Risk Score
Security misconfiguration score: missing HSTS/CSP/XFO, cookies without `Secure`/`HttpOnly`/`SameSite`, no CSRF protection, absent MFA.

### D. AI Features Roadmap

All Python-native microservices consuming the same `PageArtifact` produced by scans.

| Phase | Feature | Approach |
|---|---|---|
| **1** | **Unknown Auth Provider Classifier** — classify custom/unseen auth stacks not in the signature DB | Fine-tuned DistilBERT/CodeBERT over concatenated script URLs + inline JS + request domains → labels: `custom_oauth`, `custom_saml`, `unknown`. Retrained weekly from feedback loop data. |
| **2** | **Captcha Visual Classifier** — catch obfuscated captcha deployments that hide script domains | YOLOv8/CLIP vision model on login-page screenshots → bounding box + type (`recaptcha_checkbox`, `turnstile_invisible`). Training set generated from our own labeled scans. |
| **2** | **Difficulty & Risk Model** — replace heuristic scoring with learned models | XGBoost/LightGBM on features (WAF signal count, captcha type, fingerprinting count, missing headers, JS challenge size), labeled by historical automation success/failure. SHAP explanations shipped in reports. |
| **3** | **Auto Signature Generation** — keep the signature DB current when vendors change infrastructure | Feed HAR + headers + scripts of an unknown WAF to an LLM (GPT-4o / Llama 3 70B); prompt generates candidate YAML signature → human approves → auto PR to signature repo. |
| **3** | **Anomaly Detection for Change Tracking** — alert on meaningful protection changes | Embed DOM + script list (`text-embedding-3-small`), store vectors in pgvector; cosine distance vs last 7 days above threshold triggers alert: *"Login protection changed from reCAPTCHA to Turnstile."* |
| **3** | **NL Report Summarizer** — human-readable summaries of every report | LLM converts structured JSON report into prose: *"This login uses Auth0 with password + Google OAuth, protected by invisible Turnstile and DataDome..."* |

---

## How It Works

### Architecture

```
Client (Dashboard / SDK / API)
        │
        ▼
┌──────────────────────────────┐
│   API Gateway (FastAPI)      │
│   - API key / JWT auth       │
│   - Validation               │
│   - Rate limiting (Redis)    │
│   - Scan cache (6h TTL)      │
└──────────┬───────────────────┘
           │ create scan row (status=queued)
           ▼
┌──────────────────────────────┐
│  Celery Queue (Redis/RMQ)    │
└──────────┬───────────────────┘
           ▼
┌─────────────────────────────────────────────┐
│  Celery Workers                             │
│                                             │
│  ┌──────────────┐   ┌────────────────────┐  │
│  │ Proxy Manager│──▶│ Browser Manager    │  │
│  │ (residential │   │ (isolated context: │  │
│  │  pool, per-  │   │  proxy, UA, view-  │  │
│  │  country)    │   │  port, stealth)    │  │
│  └──────────────┘   └─────────┬──────────┘  │
│                               ▼             │
│                    ┌────────────────────┐   │
│                    │ Page Controller    │   │
│                    │ (Playwright async) │   │
│                    └─────────┬──────────┘   │
│            ┌─────────────────┼─────────────┐│
│            ▼                 ▼             ▼│
│   Network Interceptor   Runtime Analyzer  Static Analyzer
│   (CDP: req/res,        (early hooks on   (DOM, scripts,
│    headers, cookies)     fetch/XHR,        meta tags)
│                          global objects)   │
│            └─────────────────┼─────────────┘│
│                              ▼              │
│              ┌──────────────────────────┐   │
│              │  Detection Pipeline      │   │
│              │  (parallel detectors):   │   │
│              │   AuthProviderDetector   │   │
│              │   SecurityDetector       │   │
│              │   CaptchaDetector        │   │
│              │   WAFDetector            │   │
│              │   FingerprintDetector    │   │
│              └────────────┬─────────────┘   │
│                           ▼                 │
│              ┌──────────────────────────┐   │
│              │ Report Aggregator        │   │
│              │ (conflict resolution,    │   │
│              │  confidence merging,     │   │
│              │  scoring)                │   │
│              └────────────┬─────────────┘   │
└───────────────────────────┼─────────────────┘
                            ▼
        ┌───────────────────────────────────────┐
        │ Evidence Aggregator                   │
        │  HAR/PNG/DOM/trace → S3 / MinIO       │
        │  Structured report → PostgreSQL       │
        │  Time-series metrics → ClickHouse/TimescaleDB │
        └───────────────┬───────────────────────┘
                        ▼
              ┌──────────────────┐
              │ Webhook Dispatcher│
              └──────────────────┘

Signature Service (CRON): DB → in-memory cache in workers (hot reload)
```

Supporting services: Elasticsearch + Kibana (request logs/search), Prometheus + Grafana (metrics), OpenTelemetry (tracing).

### Scan Lifecycle (data flow for one scan)

1. **API receives URL** → normalizes it → creates `scan_id` row (`status=queued`) → enqueues Celery job. If a fresh result (<6h old) exists and `force=true` wasn't passed, returns cached result.
2. **Worker acquires resources**: isolated browser context with unique fingerprint (rotated real user-agent, randomized viewport), assigned residential proxy.
3. **Instrumentation enabled**: CDP domains `Network`, `Page`, `Security`; HAR capture started; Playwright tracing started.
4. **Early hooks injected** (`evaluateOnNewDocument`) so all `fetch`/XHR calls are logged *before* any page script runs.
5. **Navigation**: `goto` until `networkidle`, then wait an extra 5s for lazy-loaded captcha widgets.
6. **Collection**: all requests/responses, headers, cookies, `window` globals, DOM, certificate info.
7. **Detection**: 5 detectors run in parallel over the aggregated `PageArtifact` → merge → resolve conflicts → compute scores → persist results + evidence.
8. **Delivery**: status → `completed`; webhook dispatched (or client polls `GET /v1/scans/{scan_id}`).

On failure modes: first-request 403/challenge → one retry through a different proxy country → if still blocked, scan completes as `waf_blocked` (which is itself valuable intelligence).

---

## Detection Details

### Multi-signal confidence model

Each detector emits findings with per-signal evidence:

```json
{
  "finding": "auth_provider",
  "provider": "auth0",
  "confidence": 0.97,
  "matched_signals": [
    {"type": "script_src", "value": "https://cdn.auth0.com/js/auth0-spa-js/2.0/auth0-spa-js.production.js"},
    {"type": "global_object", "value": "window.auth0Client"},
    {"type": "network", "value": "https://example.us.auth0.com/.well-known/openid-configuration"}
  ]
}
```

Confidence increases with independent corroborating signals; conflicting signals (e.g., two providers both matching) are resolved by the aggregator using signal specificity weights.

### Signature format

Signatures are declarative YAML, versioned, hot-reloadable:

```yaml
# signatures/antibot.yaml
- name: cloudflare_turnstile
  type: captcha
  category: antibot
  confidence: 0.95
  signals:
    script_src: "challenges.cloudflare.com/turnstile"
    dom: "cf-turnstile"
    network: "challenges.cloudflare.com/cdn-cgi/challenge-platform"
```

```yaml
# signatures/auth.yaml
- name: auth0
  type: auth_provider
  category: auth
  confidence: 0.9
  signals:
    script_src: "cdn.auth0.com"
    global_object: ["auth0", "auth0Client", "webAuth"]
    network: ".well-known/openid-configuration"
    form_action: "/u/login"
```

See [Signature System](#signature-system).

---

## Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Core engine | Python 3.11+, `playwright-python` (async) | Best-in-class browser automation with CDP access; Python unlocks the AI roadmap |
| API layer | FastAPI + Pydantic v2 + Uvicorn | Async-first, typed, auto OpenAPI docs |
| Job orchestration | Celery + Redis (or RabbitMQ) | Every scan is a durable job; retries, priorities, bulk fan-out |
| Browser farm | Kubernetes + `browserless/playwright` image, or self-managed Playwright pool (`playwright-chromium`) | 1 pod = 5 concurrent browser contexts; memory-based HPA |
| Primary OLTP | PostgreSQL 15 | Scans, users, API keys, signatures, findings (JSONB evidence) |
| Time-series history | ClickHouse or TimescaleDB | Fast historical diffs across thousands of scans per URL |
| Object storage | S3 / MinIO | HAR files, screenshots, traces, DOM snapshots |
| Cache / rate limit / broker | Redis | Result cache, rate limiter, Celery backend |
| Search & logs | Elasticsearch + Kibana | Request-level log search |
| Observability | Prometheus + Grafana, OpenTelemetry | Metrics + distributed tracing |
| Signatures | YAML in Git → Postgres, versioned | Review workflow + runtime updates without deploys |
| Agent integration | Model Context Protocol (`mcp` SDK) | Exposes the scan API as MCP tools for local or networked agents |

---

## Database Schema

### PostgreSQL

```sql
-- Core scan record
CREATE TABLE scans (
  id UUID PRIMARY KEY,
  url TEXT NOT NULL,
  normalized_url TEXT,
  status TEXT,                  -- queued, running, completed, failed, waf_blocked
  difficulty_score INT,
  security_score INT,
  created_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ
);

CREATE TABLE auth_findings (
  id UUID PRIMARY KEY,
  scan_id UUID REFERENCES scans(id),
  provider VARCHAR(50),         -- auth0, okta, custom...
  flow TEXT[],                  -- [oauth_code, password, webauthn]
  confidence FLOAT,
  evidence JSONB                -- {matched_signals: [...]}
);

CREATE TABLE security_findings (
  scan_id UUID REFERENCES scans(id),
  has_csrf BOOLEAN,
  has_hsts BOOLEAN,
  has_csp BOOLEAN,
  cookie_flags JSONB,
  mfa_detected BOOLEAN,
  raw_headers JSONB
);

CREATE TABLE antibot_findings (
  scan_id UUID REFERENCES scans(id),
  captcha_type VARCHAR(50),     -- recaptcha_v3, turnstile, hcaptcha...
  captcha_visible BOOLEAN,
  waf_providers TEXT[],         -- [cloudflare, datadome]
  fingerprinting_signals TEXT[],
  cookies_detected TEXT[],      -- [__cf_bm, _abck]
  evidence JSONB
);

CREATE TABLE artifacts (
  scan_id UUID REFERENCES scans(id),
  har_url TEXT,                 -- S3 path
  screenshot_url TEXT,
  dom_snapshot_url TEXT
);

-- Signature versioning
CREATE TABLE signatures (
  id SERIAL PRIMARY KEY,
  category TEXT,                -- auth, antibot
  name TEXT,
  yaml_definition JSONB,
  version INT,
  active BOOLEAN
);
```

Additional tables (users, api_keys, webhooks, feedback/false_positives, proxy_pools). ClickHouse/TimescaleDB stores per-scan time-series snapshots powering the diff feature; pgvector (Phase 3) stores DOM/script embeddings for anomaly alerts.

---

## API Reference

Base URL: `https://api.authscope.dev/v1`

Authentication: API key via `X-API-Key` header. Default rate limit: **60 requests/min per key**.

### Create scan

```http
POST /v1/scans
X-API-Key: <your-key>
Content-Type: application/json

{
  "url": "https://example.com/login",
  "options": {
    "proxy_country": "us",
    "capture_har": true,
    "deep_scan": true,
    "force": false
  }
}
```

Response `202 Accepted`:

```json
{ "scan_id": "7b9c0f2a-...", "status": "queued" }
```

Options:

| Option | Type | Default | Description |
|---|---|---|---|
| `proxy_country` | string | auto | ISO country for exit node |
| `capture_har` | bool | `true` | Store full HAR artifact |
| `deep_scan` | bool | `false` | Extended waits, secondary navigation paths, more aggressive captcha-wait |
| `force` | bool | `false` | Bypass the 6-hour result cache |

### Get report

```http
GET /v1/scans/{scan_id}
```

Returns status plus, when completed, the full report:

```json
{
  "scan_id": "7b9c0f2a-...",
  "url": "https://example.com/login",
  "status": "completed",
  "created_at": "...",
  "completed_at": "...",
  "auth": {
    "provider": "auth0",
    "confidence": 0.97,
    "flows": ["oauth_code", "password"],
    "evidence": [...]
  },
  "security": {
    "risk_score": 34,
    "has_hsts": true,
    "has_csp": false,
    "cookie_flags": {...},
    "csrf_detected": true,
    "mfa_detected": true,
    "raw_headers": {...}
  },
  "antibot": {
    "difficulty_score": 78,
    "difficulty_reasoning": "...",
    "captcha": { "type": "turnstile_invisible", "visible": false },
    "waf_providers": ["cloudflare"],
    "fingerprinting": ["fingerprintjs_pro"],
    "cookies": ["__cf_bm"]
  },
  "artifacts": {
    "har_url": "https://s3.../scans/.../har.json",
    "screenshot_url": "https://s3.../scans/.../page.png",
    "dom_snapshot_url": "https://s3.../scans/.../dom.html"
  }
}
```

### Bulk scan

```http
POST /v1/scans/bulk
Content-Type: text/csv

url
https://site-a.com/login
https://site-b.com/signin
```

Accepts up to 1000 URLs; returns a batch id and per-URL scan ids.
Track progress via `GET /v1/scans/bulk/{batch_id}` (total + per-status counts).

### Other endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/scans?query=&filter=` | List/search your scans (pagination, filters by provider, captcha type, scores) |
| `GET` | `/v1/scans/{id}/diff?days=30` | Historical diff against prior scans |
| `POST` | `/v1/scans/{id}/feedback` | Flag false positives / confirm detections |
| `GET` | `/v1/signatures` | List active signatures (debugging/transparency) |
| `POST` | `/v1/webhooks` | Register webhook endpoints |
| `GET` | `/v1/webhooks/dlq` | List dead-lettered deliveries (re-drive candidates) |
| `POST` | `/v1/webhooks/dlq/{id}/redrive` | Re-deliver one dead-lettered webhook |

### MCP server (agent integration)

AuthScope ships a [Model Context Protocol](https://modelcontextprotocol.io) server so agents can drive scans directly. It wraps the same `/v1` API and is an optional extra:

```bash
pip install -e ".[mcp]"          # or: uvx --from 'authscope[mcp]' authscope-mcp
export AUTHSCOPE_API_URL=http://localhost:8000
export AUTHSCOPE_API_KEY=...
authscope-mcp                    # stdio (default)
authscope-mcp --transport http --port 8765   # Streamable HTTP
```

Tools: `create_scan`, `get_scan`, `wait_for_scan`, `scan_and_wait`, `list_scans`, `get_diff`, `bulk_scan`, `bulk_progress`, `submit_feedback`, `feedback_stats`, `health`. Setup, agent config, and security notes live in [`docs/MCP.md`](docs/MCP.md).

### Webhook payload

On scan completion, registered endpoints receive a signed POST containing the same report JSON as `GET /v1/scans/{id}`. Failed deliveries retry with exponential backoff, then land in the DLQ (`GET /v1/webhooks/dlq`) for manual re-drive.

---

## Signature System

The signature database is designed to be updated **without deploying code**:

1. Signatures live as YAML files in Git (`signatures/auth.yaml`, `signatures/antibot.yaml`, `signatures/fingerprinting.yaml`) — reviewed via PR.
2. CI loads them into the Postgres `signatures` table with a bumped `version`.
3. The Signature Service (CRON + push trigger) pulls active signatures and pushes them into workers' in-memory caches.
4. Workers reload atomically mid-flight — running scans finish on their loaded revision; new scans pick up the new set immediately.
5. Every signature has `version` + `active` flag, enabling rollback and A/B testing of new rules.

This closes the loop with the Phase-3 LLM auto-signature generator: new vendor infrastructure changes → LLM drafts candidate YAML → human approves PR → live within minutes.

---

## Production Considerations

### Scanner anti-detection (for accurate detection, not evasion abuse)
- Rotate user-agengers from a real-world UA dataset; randomize viewport per context
- Disable `navigator.webdriver`; apply `playwright-stealth` equivalent patches
- Residential proxies with per-country routing; identity pool rotation for repeat targets

### Resource limits
- Hard kill of browser contexts after **45 s**
- Budget ~150 MB RAM per context; K8s HPA scaled on worker memory
- Context-per-scan isolation; no shared state between scans

### Reliability
- One automatic retry on initial-block (403/challenge) with a different proxy country; final state `waf_blocked` rather than failure
- Result caching: identical URLs served from cache for 6 hours unless `force=true`
- Webhook retries with exponential backoff; dead-letter queue for undeliverable hooks

### Security of the service itself
- Browsers run sandboxed with no filesystem access
- PII stripped from stored DOM snapshots before persistence
- Secrets/API keys encrypted at rest; evidence buckets private with signed short-lived URLs

### Compliance & ethics
- Optional robots.txt respect mode (flag per scan or org-wide)
- Explicit disclaimer in all outputs: AuthScope detects and reports; it does not bypass protections
- Designed for auditing sites you own, have permission to test, or for lawful research purposes

---

## Project Structure (planned)

```
authscope/
├── api/                      # FastAPI app
│   ├── routes/               # scans, bulk, signatures, webhooks
│   ├── auth.py               # API key auth + rate limiting
│   └── schemas.py            # Pydantic v2 models
├── engine/                   # Core detection engine
│   ├── browser/              # BrowserContextManager, proxy manager
│   ├── page/                 # PageController, interceptors, early hooks
│   ├── artifacts.py          # PageArtifact model
│   └── detectors/
│       ├── base.py           # Detector ABC
│       ├── auth_provider.py
│       ├── security.py
│       ├── captcha.py
│       ├── waf.py
│       └── fingerprinting.py
├── pipeline/                 # Orchestration, aggregation, scoring
│   ├── aggregator.py         # Conflict resolution + confidence merge
│   └── scoring.py            # Difficulty + risk scores
├── workers/                  # Celery tasks, signature loader/cache
├── signatures/               # YAML source of truth
│   ├── auth.yaml
│   ├── antibot.yaml
│   └── fingerprinting.yaml
├── db/                       # Migrations, models (Postgres, ClickHouse)
├── dashboard/                # Web UI
├── mcp_server/               # MCP server for agent access (stdio / HTTP / SSE)
├── ai/                       # Phase 1+ microservices (classifier, vision, scoring)
└── tests/
```

---

## Roadmap

| Phase | Scope |
|---|---|
| **MVP** | Single scan API, 5 core detectors, ~40 provider + top-10 antibot signatures, difficulty/risk heuristic scoring, HAR/screenshot evidence, Postgres + Redis + Celery |
| **Phase 1** | Bulk CSV scans, dashboard MVP, webhook delivery, historical diff (Timescale), Unknown Auth Classifier (DistilBERT), feedback loop |
| **Phase 2** | Captcha visual classifier (YOLOv8/CLIP), ML difficulty model (XGBoost + SHAP), proxy/identity pool management UI, Elasticsearch log search |
| **Phase 3** | LLM auto-signature generation with approval workflow, embedding-based change anomaly detection (pgvector), NL report summarizer, public marketplace-ready API |

---

## Getting Started

```bash
git clone https://github.com/your-org/authscope.git
cd authscope
make install            # venv, deps, chromium
make compose-up         # postgres + redis + minio
make db-upgrade         # schema migrations
.venv/bin/python -m db.seed       # dev API key ("dev-key")
make signatures-load    # load 74 detection signatures (.venv/bin/python -m db.load_signatures)

# terminal 1
make run-api            # http://localhost:8000 (docs at /docs)
# terminal 2
make run-worker

# dashboard at http://localhost:8000/dashboard/
```

Scan something:

```bash
curl -X POST http://localhost:8000/v1/scans \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/login"}'
# → 202 {"scan_id": "...", "status": "queued"}

curl http://localhost:8000/v1/scans/<scan_id> -H "X-API-Key: dev-key"
```

Or drive it from an agent over MCP (`make install` includes the extra):

```bash
export AUTHSCOPE_API_KEY=dev-key
authscope-mcp            # stdio; see docs/MCP.md for HTTP and agent config
```

Other useful commands: `make test` (130 tests), `make coverage` (90% overall), `make lint`.

**Production:** see `Dockerfile.api` / `Dockerfile.worker`, Kubernetes manifests in
`deploy/k8s/`, Grafana dashboard in `deploy/grafana/`, alert rules in
`deploy/prometheus/alerts.yml`, and `docs/RUNBOOK.md`. Load-test with
`scripts/loadtest.py`.

---

## License

Proprietary — see [LICENSE](./LICENSE). Contact hello@authscope.dev for licensing inquiries.

## Disclaimer

AuthScope performs passive detection and reporting only. It does not solve captchas, bypass bot protection, or automate logins. Users are responsible for ensuring their use complies with applicable terms of service and laws.
