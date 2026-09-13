# AuthScope MCP Server

AuthScope exposes its scan API as a [Model Context Protocol](https://modelcontextprotocol.io)
server, so an agent can run scans, read reports, diff history, drive bulk batches
and record feedback without hand-rolling HTTP calls.

The server is a thin client over the existing `/v1` API — it adds no new
endpoints and reuses API-key auth, rate limiting and ownership scoping.

---

## Install

The MCP server is an optional extra (`mcp` SDK):

```bash
pip install -e ".[mcp]"                 # from a checkout
# or run without installing into the project venv:
uvx --from 'authscope[mcp]' authscope-mcp
```

Available as both a console script (`authscope-mcp`) and a module
(`python -m mcp_server`).

> The extra pins `mcp>=1.2,<2`. mcp 2.x renamed `FastMCP` to `MCPServer`; that
> migration is tracked separately.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `AUTHSCOPE_API_URL` | `http://localhost:8000` | AuthScope API base URL |
| `AUTHSCOPE_API_KEY` | _(required)_ | API key; sent as `X-API-Key`. Never logged or echoed in tool output. |
| `AUTHSCOPE_MCP_TOKEN` | _(unset)_ | Bearer token required for `--allow-remote` HTTP binding |

Start the API first (`make run-api`, or `make compose-up`), load signatures
(`make signatures-load`), and run a worker (`make run-worker`) for async scans.

---

## Transports

### stdio (default, for local agent config)

```bash
authscope-mcp
```

### Streamable HTTP (SSE-capable, for networked agents)

```bash
authscope-mcp --transport http --host 127.0.0.1 --port 8765
# MCP endpoint: http://127.0.0.1:8765/mcp
```

### Legacy SSE

```bash
authscope-mcp --transport sse --host 127.0.0.1 --port 8765
```

### Remote exposure

HTTP binds **loopback only** by default. To bind another host you must opt in
*and* set a bearer token, because the MCP process holds the AuthScope API key:

```bash
export AUTHSCOPE_MCP_TOKEN=$(openssl rand -hex 32)
authscope-mcp --transport http --host 0.0.0.0 --port 8765 --allow-remote
```

Requests must then send `Authorization: Bearer $AUTHSCOPE_MCP_TOKEN`.

---

## Tools

| Tool | Purpose |
|---|---|
| `health` | API reachability + whether the API key is accepted |
| `create_scan(url, proxy_country?, deep_scan?, force?)` | Queue a scan → `{scan_id, status, cached}` |
| `get_scan(scan_id, include_raw?)` | Fetch a scan; compact summary by default |
| `wait_for_scan(scan_id, timeout_s?, poll_s?, include_raw?)` | Block until terminal |
| `scan_and_wait(url, ...)` | Create + wait in one call |
| `list_scans(limit?, offset?, provider?, captcha_type?, waf_provider?, min_difficulty?, max_difficulty?, status?)` | List/filter your scans |
| `get_diff(scan_id, days?)` | Changes vs the prior scan of the same URL |
| `bulk_scan(csv_body)` | Submit a CSV (`url` header, ≤1000 rows) |
| `bulk_progress(batch_id)` | Per-status progress for a batch |
| `submit_feedback(scan_id, finding_kind, verdict, signature_name?, comment?)` | Record a verdict (`correct` / `false_positive`) |
| `feedback_stats()` | Per-signature confirmation / false-positive rates |

### Response shaping

Terminal scans (`completed`, `waf_blocked`) return a compact `summary`
(provider, scores, WAF/captcha, presigned artifact links). Pass
`include_raw=true` for the full report; long strings (deep-scan bodies) are
truncated. Queued/running/failed payloads are returned as-is.

`wait_for_scan` and `scan_and_wait` return the last observed status plus
`timed_out: true` instead of hanging.

### Errors

API errors (`{"detail": {"code", "message"}}`) become MCP tool errors with an
actionable hint:

- `401` → check `AUTHSCOPE_API_KEY` (missing/inactive)
- `404` → scan/batch not found or not owned by this key
- `429` → rate limited; retry after the `Retry-After` value
- `unreachable` → the API at `AUTHSCOPE_API_URL` isn't running

---

## Agent configuration

### OpenCode (`opencode.json`)

Local (stdio):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "authscope": {
      "type": "local",
      "command": ["authscope-mcp"],
      "environment": {
        "AUTHSCOPE_API_URL": "http://localhost:8000",
        "AUTHSCOPE_API_KEY": "${AUTHSCOPE_API_KEY}"
      },
      "enabled": true
    }
  }
}
```

Remote (Streamable HTTP):

```json
{
  "mcp": {
    "authscope": {
      "type": "remote",
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer ${AUTHSCOPE_MCP_TOKEN}" },
      "enabled": true
    }
  }
}
```

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "authscope": {
      "command": "authscope-mcp",
      "env": {
        "AUTHSCOPE_API_URL": "http://localhost:8000",
        "AUTHSCOPE_API_KEY": "..."
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add authscope \
  --env AUTHSCOPE_API_URL=http://localhost:8000 \
  --env AUTHSCOPE_API_KEY=... \
  -- authscope-mcp
```

---

## Security notes

- Scans are **detection-only**. Tools report findings; they do not bypass
  captchas or WAFs. Reports carry the standard detection-only disclaimer.
- The MCP process is a trust boundary: it can act as your API key. Prefer
  stdio, or loopback HTTP; only use `--allow-remote` behind TLS with a strong
  `AUTHSCOPE_MCP_TOKEN`.
- Tool output never contains the API key.
- Scanning is still subject to AuthScope's SSRF guard, per-key rate limits and
  ownership scoping.

---

## Testing

```bash
pytest tests/test_mcp_server.py
```

The suite drives the tools against the API in-process via
`httpx.ASGITransport` (MCP tool → client → FastAPI → eager worker), covering
the happy path, 401/429 mapping, poll timeout, bulk, diff and feedback.
