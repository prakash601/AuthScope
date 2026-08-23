# AuthScope — Implementation Plan & Issue Tracker

> **This is the single source of truth for all implementation issues, in execution order.**
> When an issue is completed: mark its Status as ✅ Completed here and check its acceptance criteria.
> After completing an issue, append a detailed entry (what was done, limitations) to [`BUILD_LOG.md`](./BUILD_LOG.md).

**Legend:** ⬜ Not started · 🔵 In progress · ✅ Completed · ⏸️ Blocked

---

## Milestone Overview

| Milestone | Scope | Issues | Status |
|---|---|---|---|
| **M0 — Foundation** | Repo scaffold, dev environment, database | ISS-001 – ISS-004 | ✅ |
| **M1 — Core Detection Engine** | Browser automation, artifact capture, signatures, detectors | ISS-005 – ISS-014 | ✅ |
| **M2 — Pipeline & Scoring** | Aggregation, conflict resolution, scores | ISS-015 – ISS-016 | ✅ |
| **M3 — API & Orchestration** | FastAPI, Celery jobs, webhooks, caching | ISS-017 – ISS-023 | ✅ |
| **M4 — Platform & Hardening** | Dashboard, diff, feedback loop, observability, CI | ISS-024 – ISS-029 | ✅ |

Dependency rule: within a milestone, issues must be done in order unless explicitly marked "parallelizable".

---

## M0 — Foundation

### ISS-001 — Repository scaffold & toolchain
**Status:** ✅

**What it does:** Create the Python project skeleton matching the planned layout (`api/`, `engine/`, `pipeline/`, `workers/`, `signatures/`, `db/`, `tests/`), with dependency management, formatting, linting, and type checking configured so every later issue has a stable baseline.

**Tasks:**
- [x] `pyproject.toml` (deps: fastapi, pydantic v2, uvicorn, celery, redis, playwright, sqlalchemy 2.0, alembic, httpx, structlog)
- [x] Dev deps: ruff (lint+format), mypy, pytest, pytest-asyncio
- [x] Directory skeleton with `__init__.py`
- [x] `.env.example`, `.gitignore`, Makefile (`make lint test run`)
- [x] Git init, first commit

**Acceptance criteria:**
- [x] `make lint` and `make test` pass on a clean clone
- [x] `python -c "import api, engine, pipeline, workers"` succeeds
- [x] README "Getting Started" commands match actual setup

---

### ISS-002 — Local dev environment (Docker Compose)
**Status:** ✅

**What it does:** One-command startup of all infrastructure services for local development.

**Tasks:**
- [x] `docker-compose.yml`: postgres:15, redis:7, minio (S3-compatible), adminer/pgadmin optional
- [x] Health checks + startup ordering
- [x] Named volumes; MinIO bucket auto-created via init script
- [x] Env var wiring shared with app config

**Acceptance criteria:**
- [x] `docker compose up -d` brings up all services healthy
- [x] Postgres reachable at `localhost:5432`, Redis at `6379`, MinIO at `9000`
- [x] Restarting compose retains data

---

### ISS-003 — Configuration & settings module
**Status:** ✅

**What it does:** Single typed settings object (Pydantic `BaseSettings`) loaded from env/.env used by every component — no scattered `os.getenv`.

**Tasks:**
- [x] `config.py` with grouped settings: Database, Redis, S3, Scan (timeouts, cache TTL), Auth, Proxy
- [x] Validation with clear error messages on missing required vars
- [x] Unit tests for defaults and failure cases

**Acceptance criteria:**
- [x] `get_settings()` returns validated config from `.env`
- [x] Missing mandatory var raises actionable error naming the variable
- [x] Test coverage ≥ 90% for this module

---

### ISS-004 — Database schema & migrations
**Status:** ✅

**What it does:** Implement the full PostgreSQL schema (scans, auth_findings, security_findings, antibot_findings, artifacts, signatures, users, api_keys, webhooks, feedback) with Alembic migrations and SQLAlchemy async models.

**Tasks:**
- [x] SQLAlchemy 2.0 async models mirroring the schema in README §Database Schema
- [x] Alembic initial migration
- [x] Indexes: `scans(normalized_url, created_at)`, `scans(status)`, findings by scan_id
- [x] Seed script for dev API key

**Acceptance criteria:**
- [x] `alembic upgrade head` creates all tables on empty DB
- [x] `alembic downgrade base` cleanly reverses
- [x] Model round-trip test (insert scan + all findings, read back intact incl. JSONB/arrays)

---

## M1 — Core Detection Engine

### ISS-005 — Browser Context Manager
**Status:** ✅

**What it does:** Playwright-based manager producing isolated browser contexts with per-scan fingerprint (rotated real UA, randomized viewport), proxy assignment, tracing enabled, and hard 45s lifecycle kill. `ignore_https_errors=False`.

**Tasks:**
- [x] `BrowserContextManager.get_context(proxy_url, fingerprint)` per LLD
- [x] Fingerprint generator: UA dataset rotation, viewport randomization, locale/timezone
- [x] Stealth patches: disable `navigator.webdriver`
- [x] Context lifecycle: acquire/release, RAM guard, 45s watchdog kill
- [x] Playwright tracing start/stop wired to context

**Acceptance criteria:**
- [x] Integration test launches context against a local test page, collects title, releases cleanly
- [x] Watchdog kills a hung context within 45s (test with artificial stall)
- [x] Two concurrent contexts have distinct UA + viewport

---

### ISS-006 — Page Controller & network interception (CDP)
**Status:** ✅

**What it does:** Navigates pages and captures the complete request/response record: enable CDP Network/Page/Security domains, HAR capture, response headers, Set-Cookie parsing, certificate/security details.

**Tasks:**
- [x] `PageController.goto(url, wait="networkidle")` + configurable extra 5s lazy-captcha wait
- [x] CDP session attach; subscribe request/requestWillBeSent/responseReceived events
- [x] HAR generation (Playwright HAR or manual assembly from captured events)
- [x] Cookie store snapshot post-load
- [x] Screenshot (full-page PNG) capture
- [x] Timeout/blocked-page detection (interstitials, challenge pages) surfaced as scan state

**Acceptance criteria:**
- [x] Against a local fixture site: every request/response (incl. XHR/fetch triggered by scripts) is captured with headers
- [x] HAR file is valid JSON and loadable by HAR viewers
- [x] Screenshot PNG produced non-empty
- [x] A page served with 403 + challenge HTML results in detected state, not silent success

---

### ISS-007 — Runtime analyzer (early JS hooks)
**Status:** ✅

**What it does:** Injects hooks via `evaluateOnNewDocument` before any page script runs, recording all fetch/XHR calls and probing global objects — capturing signals static analysis can't see.

**Tasks:**
- [x] Wrap `window.fetch` and `XMLHttpRequest.open/send` to log method+URL+initiator
- [x] Periodic/global-object probe: collect enumerable `window` properties of interest at load-complete
- [x] Hook buffer drained into artifact at scan end (survives navigation via injection per frame)
- [x] Ensure hooks are non-breaking (try/catch guards, never alter page behavior)

**Acceptance criteria:**
- [x] Fixture page making fetch/XHR on load shows all calls in hook log with correct URLs
- [x] Hooks active before first third-party script executes (verified ordering)
- [x] Pages with CSP still function normally with hooks injected (no console errors caused by us beyond CSP reports we control)

---

### ISS-008 — Static analyzer (DOM/scripts/meta)
**Status:** ✅

**What it does:** Extracts everything needed for DOM-level detection: form elements/actions/inputs, script src list, inline script text, hidden inputs (CSRF/honeypot candidates), meta tags, iframe sources, autocomplete attributes.

**Tasks:**
- [x] DOM serialization snapshot (post-load)
- [x] Extractors: forms (+action/method/fields), script srcs, inline JS blobs, iframes, metas
- [x] Honeypot heuristics inputs (hidden/offscreen/naming patterns) — detection itself lives in detectors
- [x] PII stripping pass over stored DOM snapshot (emails, phone patterns, token-like params redacted)

**Acceptance criteria:**
- [x] Fixture login page yields correct form action, input list, script list
- [x] Hidden input with name "bot-field" flagged as honeypot candidate
- [x] Stored DOM contains zero raw email addresses (test with planted ones)

---

### ISS-009 — PageArtifact model
**Status:** ✅

**What it does:** The single immutable data object passed to all detectors, unifying outputs of ISS-006/007/008: requests, responses, headers, cookies, globals, DOM structures, screenshot ref, timing.

**Tasks:**
- [x] Pydantic models: `PageArtifact` + nested types (`CapturedRequest`, `CookieInfo`, `DomSummary`, `GlobalProbe`)
- [x] Factory/builder aggregating collector outputs
- [x] Serialization to/from JSON (for persistence + future AI microservices consuming artifacts)

**Acceptance criteria:**
- [x] End-to-end test: navigate fixture site → build artifact → serialize → deserialize losslessly
- [x] Artifact JSON schema documented (docstrings/example committed)

---

### ISS-010 — Signature system (YAML → Postgres → worker cache) + initial signatures
**Status:** ✅

**What it does:** The hot-reloadable signature pipeline plus the seed content: ~40 auth provider signatures and top antibot/captcha/WAF/fingerprinting signatures in YAML format per README.

**Tasks:**
- [x] YAML schema definition + validation (name, category, type, confidence, signals dict, version)
- [x] Loader: parse YAML dir → upsert into `signatures` table with version bump, active flag
- [x] Worker-side in-memory cache with atomic reload (CRON/push trigger stub)
- [x] Seed files: `signatures/auth.yaml` (auth0, firebase, okta, cognito, clerk, azure_ad, keycloak, onelogin, ping, supabase, workos, etc.), `signatures/antibot.yaml` (cloudflare, datadome, perimeterx, akamai, kasada, imperva), `signatures/captcha.yaml` (recaptcha v2/v3, hcaptcha, turnstile, arkose, geetest), `signatures/fingerprinting.yaml` (fingerprintjs, castle, sift, creepjs)
- [x] CLI: `python -m db.load_signatures`

**Acceptance criteria:**
- [x] All seed YAML validates against schema; ≥40 auth provider entries present
- [x] Loading twice bumps version once and doesn't duplicate rows (idempotent)
- [x] Runtime test: add a dummy signature to YAML → trigger reload → new detector run matches it without process restart

---

### ISS-011 — Detector interface + parallel pipeline runner
**Status:** ✅

**What it does:** The strategy-pattern core: `Detector` ABC taking `PageArtifact` returning findings; async runner executing all registered detectors concurrently with isolation (one detector's crash doesn't fail the scan).

**Tasks:**
- [x] `Detector(ABC)` with `detect(artifact) -> list[Finding]`; `Finding` model with signal evidence
- [x] Registry + `asyncio.gather` runner with per-detector timeout and exception containment
- [x] Structured logging per detector (duration, finding counts)

**Acceptance criteria:**
- [x] Runner test with mock detectors: all run concurrently, one raising exception yields partial findings not scan failure
- [x] Per-detector timeout enforced (mock slow detector cut off)

---

### ISS-012 — AuthProviderDetector
**Status:** ✅

**What it does:** Matches auth provider signatures across all four signal classes (script_src, global_object, network, form_action); correlates multi-signal hits into a confidence-scored provider + flows finding (oauth/saml/password/magic-link/webauthn/otp).

**Tasks:**
- [x] Signal matching engine for auth category signatures (substring/regex per signal type)
- [x] Flow inference rules (redirect chain to /authorize → oauth_code; password input + POST → password; navigator.credentials publicKey call → webauthn; etc.)
- [x] Confidence computation: independent corroborating signals boost; single weak signal caps low
- [x] Evidence payload: matched signals with exact matched values

**Acceptance criteria:**
- [x] Fixture pages emulating Auth0 (script+global+network signals) detect `auth0` ≥0.9 confidence
- [x] Single-signal-only fixture yields lower confidence, still attributed correctly
- [x] OAuth redirect-chain fixture classified with flow `oauth_code`
- [x] No-provider fixture yields `custom`/`unknown` finding, not false positive

---

### ISS-013 — SecurityDetector
**Status:** ✅

**What it does:** Full security header audit, cookie flag analysis, CSRF token presence, honeypot confirmation, autocomplete analysis, MFA heuristics → structured security finding.

**Tasks:**
- [x] Header audit: HSTS (+max-age/includeSubDomains/preload parsing), CSP (directive breakdown), XFO, COOP/CORP/COEP, Permissions-Policy, Referrer-Policy
- [x] Set-Cookie parser: Secure/HttpOnly/SameSite/expiry/domain on session-relevant cookies
- [x] CSRF detection: hidden token inputs (naming/dentropy patterns), meta csrf-token, double-submit cookie pattern
- [x] Honeypot confirmation combining static analyzer candidates
- [x] Password policy hints from inline JS validation patterns; MFA heuristic signals

**Acceptance criteria:**
- [x] Fixture with full header set → all flags true with parsed values; missing-header fixture → flags false
- [x] Cookie without HttpOnly/Secure correctly reported in cookie_flags JSONB
- [x] CSRF hidden input fixture detected; honeypot fixture distinguished from CSRF token
- [x] Output maps 1:1 onto `security_findings` table columns

---

### ISS-014 — CaptchaDetector, WAFDetector, FingerprintDetector *(parallelizable internally)*
**Status:** ✅

**What it does:** The three anti-bot detectors:
- **CaptchaDetector**: vendor + variant (recaptcha_v2_checkbox/invisible, recaptcha_v3_score, hcaptcha, turnstile_managed/invisible, arkose, geetest_v3/v4), visible vs invisible, score vs challenge
- **WAFDetector**: headers, detection cookies (__cf_bm, _datadome, _px*, ak_bmsc/_abck, incap_ses_*, kpsdk_*), JS challenge interstitial recognition, waf_blocked state propagation
- **FingerprintDetector**: FingerprintJS/FPJS Pro, Castle, Sift, CreepJS, vendor sensor SDK endpoints, canvas/WebGL fingerprint reads

**Tasks:**
- [x] Three detectors implementing Detector ABC against antibot/captcha/fingerprinting signature sets
- [x] Captcha visibility classification (DOM widget presence/rendered size vs script-only = invisible)
- [x] Score-vs-challenge classification (v3 always-running vs v2 event-driven markers)
- [x] WAF interstitial fingerprints (title/body markers of Cloudflare/Kasada/PX challenge pages)
- [x] Blocked-scan handling: challenge-on-first-response sets scan outcome `waf_blocked` with partial findings

**Acceptance criteria:**
- [x] Each vendor has a fixture page; detector identifies correct vendor+variant on each
- [x] Turnstile invisible fixture → `captcha_visible=false`; reCAPTCHA v2 checkbox fixture → true
- [x] Cloudflare challenge-page fixture → WAF=cloudflare + interstitial recognized
- [ `__cf_bm` cookie alone (no headers) still attributes cloudflare via cookie signal
- [x] All three run under the ISS-011 pipeline without interference

---

## M2 — Pipeline & Scoring

### ISS-015 — Report Aggregator
**Status:** ✅

**What it does:** Merges all detector findings into one report: deduplication, conflict resolution (e.g., two providers matching — resolve by signal specificity weights), confidence merging, evidence attachment, final report JSON persisted to Postgres.

**Tasks:**
- [x] Merge logic per finding category; specificity-weighted conflict resolution
- [x] Final report JSON schema (matches GET /v1/scans/{id} response shape)
- [x] Persistence to auth/security/antibot findings tables + artifacts rows
- [x] Evidence upload: HAR/screenshot/DOM/trace → MinIO/S3 paths recorded in artifacts table

**Acceptance criteria:**
- [x] Conflicting two-provider fixture resolves deterministically to higher-specificity match (documented tie-break)
- [x] Complete report round-trips through DB with all evidence URLs valid (objects retrievable)
- [x] Report JSON validates against committed JSON schema file

---

### ISS-016 — Scoring module (difficulty + risk, heuristic)
**Status:** ✅

**What it does:** Computes Automation Difficulty Score 0–100 (weighted: WAF tier > invisible/score captcha > visible captcha > fingerprinting > behavioral > honeypots) and Risk Score (missing protections), each with itemized plain-English reasoning strings. Written behind an interface so Phase-2 ML models can drop in.

**Tasks:**
- [x] Weighted scoring functions per README §Scoring tables
- [x] Reasoning generator listing contributing factors ("Score 87: Akamai + invisible Turnstile...")
- [x] `ScoringStrategy` protocol (heuristic impl now, XGBoost later)
- [x] Scores written to scans row; unit tests pinning score math

**Acceptance criteria:**
- [x] Table-driven unit tests: known finding sets produce expected exact scores
- [x] Empty findings (clean page) → difficulty near 0, risk reflects missing headers only
- [x] Reasoning string enumerates every factor contributing >0 weight

---

## M3 — API & Orchestration

### ISS-017 — FastAPI skeleton, auth & rate limiting
**Status:** ✅

**What it does:** App factory, router registration, `X-API-Key` authentication middleware backed by api_keys table, Redis-backed 60 req/min sliding window per key, structured error responses, OpenAPI docs.

**Tasks:**
- [x] App factory + lifespan (DB pool, Redis client)
- [x] API key dependency: lookup, active check, last_used update
- [x] Rate limiter middleware (Redis INCR+EXPIRE or sliding window), 429 with Retry-After
- [x] Global exception handler → consistent JSON errors; request ID + structlog access logs

**Acceptance criteria:**
- [x] Request without/invalid key → 401; valid key → pass
- [x] 61st request within a minute → 429 with correct headers; resets after window
- [x] `/docs` renders; health endpoint `/healthz` checks DB+Redis

---

### ISS-018 — POST /v1/scans + Celery job creation
**Status:** ✅

**What it does:** The main scan entrypoint: validate URL, normalize, dedupe/cache-check (6h TTL unless force=true), create scans row (queued), enqueue Celery task, return 202 with scan_id.

**Tasks:**
- [x] Request/response Pydantic schemas incl. options (proxy_country, capture_har, deep_scan, force)
- [x] URL normalization + validation (SSRF guard: block private/link-local IPs, allowlist schemes)
- [x] Result-cache lookup keyed on normalized_url
- [x] Celery app config (Redis broker/backend), task `run_scan(scan_id)`
- [x] Worker end-to-end: dequeue → run engine pipeline → persist → status transitions queued→running→completed/failed/waf_blocked

**Acceptance criteria:**
- [x] Valid request → 202 {scan_id, status:"queued"}; row exists with status queued
- [x] Same URL within 6h returns cached scan_id unless force=true
- [x] SSRF attempt (http://169.254.169.254/) rejected 400/422
- [x] Full happy-path integration test: create → worker completes → report in DB

---

### ISS-019 — GET /v1/scans/{id} + list/search endpoint
**Status:** ✅

**What it does:** Report retrieval matching the documented response shape, plus paginated list/search with filters (provider, captcha type, score ranges, status).

**Acceptance criteria:**
- [x] Completed scan returns full report incl. evidence URLs (signed, short-lived for S3/MinIO)
- [x] Queued/running scan returns status-only 200
- [x] Unknown id → 404; other-user's key's scan → 404 (no info leak)
- [x] List endpoint pagination + ≥3 filters verified by tests

---

### ISS-020 — Bulk scan (CSV)
**Status:** ✅

**What it does:** `POST /v1/scans/bulk` accepting CSV (≤1000 URLs), creating batch + individual scan jobs, fan-out to workers with concurrency control.

**Acceptance criteria:**
- [x] 1000-row CSV accepted; batch id returned with per-URL scan ids
- [x] Malformed rows skipped and reported, valid rows still processed
- [x] Batch completes with mixed outcomes (some waf_blocked) without blocking others

---

### ISS-021 — Webhook dispatcher
**Status:** ✅

**What it does:** On scan completion, signed POST of the report JSON to registered webhook URLs; retries with exponential backoff; dead-letter after max attempts.

**Acceptance criteria:**
- [x] Local receiver gets POST within seconds of completion; HMAC signature header verifiable
- [x] Failing receiver retried ≥3 times with backoff then dead-lettered (observable)
- [x] Webhook CRUD endpoints tested

---

### ISS-022 — Retry & blocked-scan policy
**Status:** ✅

**What it does:** Worker-level resilience: initial-block (403/challenge) → one retry with different proxy country → final `waf_blocked` state with whatever partial intelligence was gathered.

**Acceptance criteria:**
- [x] Simulated 403-first-then-success flow completes with real findings after retry
- [x] Persistent-block flow ends `waf_blocked`, never `failed`
- [x] Retry uses different exit country than first attempt (logged/asserted)

---

### ISS-023 — Evidence storage service (S3/MinIO)
**Status:** ✅

**What it does:** Dedicated service abstracting artifact upload/download: HAR, screenshot, DOM snapshot, trace; private bucket, short-lived signed GET URLs; lifecycle cleanup for expired artifacts.

**Acceptance criteria:**
- [x] Upload→signed-url→download round-trip works against MinIO in compose
- [x] Unsigned direct access denied (bucket private)
- [x] Signed URL expiry honored; cleanup job removes artifacts past retention

---

## M4 — Platform & Hardening

### ISS-024 — Historical diff endpoint
**Status:** ✅

**What it does:** `GET /v1/scans/{id}/diff?days=30` — compares current report vs prior scans of same normalized_url: provider changes, captcha/WAF additions/removals, header deltas, score deltas. Time-series snapshots stored for fast comparison.

**Acceptance criteria:**
- [x] Two scans with changed captcha vendor produce human-readable diff listing the change
- [x] Identical consecutive scans → empty diff
- [x] Diff computed for arbitrary day windows; performance OK on URL with 100+ historical scans

---

### ISS-025 — Feedback / false-positive endpoint
**Status:** ✅

**What it does:** `POST /v1/scans/{id}/feedback` to confirm/deny findings; stored in feedback table linked to finding + signature; feeds future tuning/retraining. Signature stats updated (match counts).

**Acceptance criteria:**
- [x] Feedback persisted and queryable per finding/signature
- [x] Invalid finding reference rejected
- [x] Aggregate false-positive rate computable per signature via SQL view

---

### ISS-026 — Observability (Prometheus + Grafana + OTel)
**Status:** ✅

**What it does:** Metrics (scan durations, queue depth, detector timings, browser context count, error rates), Grafana dashboard JSON, OpenTelemetry traces spanning API→worker→detectors.

**Acceptance criteria:**
- [x] `/metrics` exposes Prometheus format; Grafana dashboard loads with ≥6 useful panels
- [x] A single scan trace visible end-to-end in trace viewer with detector spans
- [x] Alert rules defined for: queue backlog growth, failure-rate spike, browser OOM kills

---

### ISS-027 — Test suite completion & fixtures site
**Status:** ✅

**What it does:** A self-hosted "fixture zoo" web app serving synthetic login pages (per-provider emulations, captcha variants, WAF interstitials, honeypots) used by the entire integration test suite — no external-site dependence in CI.

**Acceptance criteria:**
- [x] ≥15 fixture pages covering major detections
- [x] Full integration suite green in CI using only fixtures
- [x] Overall coverage ≥80% engine/, ≥70% project-wide; flaky tests quarantined or fixed

---

### ISS-028 — Dashboard MVP
**Status:** ✅

**What it does:** Minimal web UI: submit scan, scan list with search/filter, report view (scores, findings with evidence viewer: screenshot, HAR explorer, raw headers), diff view.

**Acceptance criteria:**
- [x] Submit URL → see live status → view full report
- [x] Evidence viewer renders screenshot + navigable HAR
- [x] Search/filter returns correct subsets; diff view renders ISS-024 output

---

### ISS-029 — Production readiness pass
**Status:** ✅

**What it does:** Deployment packaging: production Dockerfiles, K8s manifests/Helm chart for API + workers + browser pool (HPA on memory), secrets management, retention policies, robots.txt respect flag, disclaimer surfacing, load test baseline.

**Acceptance criteria:**
- [x] Deployable to a K8s cluster from repo via documented commands/values file
- [x] Load test: 50 concurrent scans sustained without OOM or queue starvation; metrics captured
- [x] Secrets via env-injected secret store only — none in images or repo
- [x] Runbook doc: common failures (waf_blocked spikes, broker down, S3 errors)

---

## Completion Protocol (for every issue)

When marking an issue ✅:
1. Check off all its acceptance criteria above (only when genuinely met).
2. Update this file's Status field and the Milestone Overview table.
3. Append an entry to [`BUILD_LOG.md`](./BUILD_LOG.md):

```markdown
## ISS-XXX — <title> (<date>)
### What was done
- ...
### Design decisions / deviations
- ...
### Limitations & known gaps
- ...
### How to verify
- ...
```
