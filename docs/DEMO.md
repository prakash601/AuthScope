# AuthScope — Showcase Demo Pack

Three canned targets, all offline (no external network). Each is demoable in seconds.

## Option A — offline pipeline demo (fastest, no DB/Redis)

```bash
PYTHONPATH=. .venv/bin/python scripts/demo.py
```

Expected (real Chromium + full 5-detector pipeline):

| Page | Expect | Scores (approx) |
|---|---|---|
| `auth0_like.html` | auth `auth0` | difficulty 0 / risk ~80 (bare fixture, no headers) |
| `turnstile_visible.html` | captcha `turnstile_managed` visible | difficulty ~25 |
| `waf_cookies.html` | waf includes `cloudflare` (+`akamai_bm` script) | difficulty ~38 |

`demo: all PASS` on success. Auth on generic fixtures may show a
best-effort provider guess — the asserted signal (auth/captcha/waf) is what
matters per row.

## Option B — full API demo (needs stack)

```bash
make compose-up && make db-upgrade
.venv/bin/python -m db.seed && make signatures-load
# terminal 1
make run-api            # http://localhost:8000 (docs at /docs)
# terminal 2
make run-worker
```

```bash
curl -X POST http://localhost:8000/v1/scans \
  -H "X-API-Key: dev-key" -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/login"}'
# → 202 {"scan_id": "...", "status": "queued"}

curl http://localhost:8000/v1/scans/<scan_id> -H "X-API-Key: dev-key"
```

Dashboard at http://localhost:8000/dashboard/: paste `dev-key` → New scan →
auto-poll → Report (scores, auth/security/antibot, evidence links) → Diff view
with `?days=30`.

## Option C — drive it from an agent (MCP)

```bash
pip install -e ".[mcp]"
export AUTHSCOPE_API_URL=http://localhost:8000
export AUTHSCOPE_API_KEY=dev-key
authscope-mcp                 # stdio; or: --transport http --port 8765
```

Add the server to your agent (see [`MCP.md`](MCP.md) for OpenCode/Claude
config) and ask it to run a scan — the agent gets tools like `scan_and_wait`,
`list_scans` and `get_diff`:

```
scan_and_wait("https://example.com/login")
→ summary: provider auth0, difficulty 0, risk 80, presigned HAR/screenshot links
```

## Evidence per scan

HAR (`startedDateTime` real ISO-8601, `time` measured), full-page PNG,
PII-stripped DOM snapshot, Playwright trace — via presigned URLs in the report.
