"""AuthScope MCP server.

Exposes the AuthScope scan API as Model Context Protocol tools so an agent can
run scans, read reports, diff history, drive bulk batches and record feedback.

Transports:

* ``stdio`` (default) — for local agent config.
* ``http`` — Streamable HTTP (SSE-capable) for networked agents.
* ``sse`` — legacy SSE transport.

Security: over stdio the process inherits the caller's trust. Over HTTP the
server holds ``AUTHSCOPE_API_KEY``, so it binds loopback only unless
``--allow-remote`` **and** a bearer token (``AUTHSCOPE_MCP_TOKEN`` or
``--token``) are supplied.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import time
from typing import Any

from mcp.server.fastmcp import FastMCP
from starlette.responses import JSONResponse
from starlette.types import Receive, Scope, Send

from mcp_server.client import TERMINAL_STATUSES, AuthScopeClient

DEFAULT_HTTP_PORT = 8765
DEFAULT_POLL_SECONDS = 2.0
DEFAULT_WAIT_SECONDS = 120.0
_TRUNCATE_LIMIT = 4000

mcp = FastMCP(
    "authscope",
    instructions=(
        "AuthScope detects login providers, anti-bot/WAF and security posture for "
        "web pages. Scans are asynchronous: create_scan returns a scan_id, then "
        "wait_for_scan (or scan_and_wait) blocks until the report is ready. Results "
        "are detection-only and must not be used to bypass protections."
    ),
)


def get_client() -> AuthScopeClient:
    """Build the API client from the environment. Monkeypatched in tests."""
    return AuthScopeClient()


# -- presentation helpers --------------------------------------------------


def _truncate(value: Any, limit: int = _TRUNCATE_LIMIT) -> Any:
    """Recursively cap long strings (deep-scan bodies can be huge)."""
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + "…[truncated]"
    if isinstance(value, dict):
        return {k: _truncate(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [_truncate(v, limit) for v in value]
    return value


def _pick(source: dict[str, Any] | None, keys: tuple[str, ...]) -> dict[str, Any] | None:
    if not source:
        return None
    return {k: source.get(k) for k in keys}


def _summarize(report: dict[str, Any]) -> dict[str, Any]:
    """Compact view of a full report: scores, provider and artifact links."""
    return {
        "scan_id": report.get("scan_id"),
        "url": report.get("url"),
        "status": report.get("status"),
        "created_at": report.get("created_at"),
        "completed_at": report.get("completed_at"),
        "auth": _pick(report.get("auth"), ("provider", "confidence", "flows", "other_providers")),
        "security": _pick(
            report.get("security"),
            ("risk_score", "mfa_detected", "has_csrf", "has_hsts", "has_csp"),
        ),
        "antibot": _pick(
            report.get("antibot"),
            ("difficulty_score", "captcha", "waf_providers", "fingerprinting_signals"),
        ),
        "artifacts": report.get("artifacts"),
        "disclaimer": report.get("disclaimer"),
    }


def _present(payload: dict[str, Any], include_raw: bool) -> dict[str, Any]:
    """Summarize terminal reports; pass through queued/running status payloads."""
    if "auth" not in payload:  # queued/running/failed status response
        return payload
    out: dict[str, Any] = {"summary": _summarize(payload)}
    if include_raw:
        out["report"] = _truncate(payload)
    return out


async def _wait_for_terminal(
    client: AuthScopeClient, scan_id: str, timeout_s: float, poll_s: float
) -> dict[str, Any]:
    deadline = time.monotonic() + max(0.0, timeout_s)
    payload = await client.get_scan(scan_id)
    while payload.get("status") not in TERMINAL_STATUSES:
        if time.monotonic() >= deadline:
            return {**payload, "timed_out": True}
        await asyncio.sleep(max(0.05, poll_s))
        payload = await client.get_scan(scan_id)
    return payload


# -- tools -----------------------------------------------------------------


@mcp.tool()
async def health() -> dict[str, Any]:
    """Check that the AuthScope API is reachable and the API key is accepted."""
    return await get_client().health()


@mcp.tool()
async def create_scan(
    url: str,
    proxy_country: str | None = None,
    deep_scan: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Queue a scan for a URL and return ``{scan_id, status, cached}``.

    Args:
        url: Target URL to scan.
        proxy_country: Optional two-letter exit country for the scan proxy.
        deep_scan: Also capture response bodies (larger evidence).
        force: Bypass the fresh-result cache and rescan.
    """
    return await get_client().create_scan(
        url,
        proxy_country=proxy_country,
        deep_scan=deep_scan,
        force=force,
    )


@mcp.tool()
async def get_scan(scan_id: str, include_raw: bool = False) -> dict[str, Any]:
    """Fetch a scan by id.

    Returns a compact summary once the scan is terminal (completed / waf_blocked
    / failed). Set ``include_raw=True`` for the full report (long bodies are
    truncated). While queued/running the status is returned as-is.
    """
    payload = await get_client().get_scan(scan_id)
    return _present(payload, include_raw)


@mcp.tool()
async def wait_for_scan(
    scan_id: str,
    timeout_s: float = DEFAULT_WAIT_SECONDS,
    poll_s: float = DEFAULT_POLL_SECONDS,
    include_raw: bool = False,
) -> dict[str, Any]:
    """Block until a scan reaches a terminal status, then return its report.

    On timeout returns the last seen status plus ``timed_out: true``.
    """
    payload = await _wait_for_terminal(get_client(), scan_id, timeout_s, poll_s)
    return _present(payload, include_raw)


@mcp.tool()
async def scan_and_wait(
    url: str,
    timeout_s: float = DEFAULT_WAIT_SECONDS,
    poll_s: float = DEFAULT_POLL_SECONDS,
    proxy_country: str | None = None,
    deep_scan: bool = False,
    force: bool = False,
    include_raw: bool = False,
) -> dict[str, Any]:
    """Create a scan and wait for its report in one call (create + poll)."""
    client = get_client()
    created = await client.create_scan(
        url,
        proxy_country=proxy_country,
        deep_scan=deep_scan,
        force=force,
    )
    scan_id = created.get("scan_id")
    if not scan_id:
        return created
    if created.get("status") in TERMINAL_STATUSES:
        payload = await client.get_scan(scan_id)
    else:
        payload = await _wait_for_terminal(client, scan_id, timeout_s, poll_s)
    presented = _present(payload, include_raw)
    if "summary" in presented:
        presented["cached"] = bool(created.get("cached"))
    return presented


@mcp.tool()
async def list_scans(
    limit: int = 50,
    offset: int = 0,
    provider: str | None = None,
    captcha_type: str | None = None,
    waf_provider: str | None = None,
    min_difficulty: int | None = None,
    max_difficulty: int | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """List recent scans for the API key's owner, with optional filters."""
    return await get_client().list_scans(
        limit=limit,
        offset=offset,
        provider=provider,
        captcha_type=captcha_type,
        waf_provider=waf_provider,
        min_difficulty=min_difficulty,
        max_difficulty=max_difficulty,
        status=status,
    )


@mcp.tool()
async def get_diff(scan_id: str, days: int = 30) -> dict[str, Any]:
    """What changed in a scan vs the most recent prior scan of the same URL."""
    return await get_client().get_diff(scan_id, days=days)


@mcp.tool()
async def bulk_scan(csv_body: str) -> dict[str, Any]:
    """Submit many URLs at once (CSV with a ``url`` header, up to 1000 rows).

    Returns ``{batch_id, accepted, skipped, results}``; poll ``bulk_progress``.
    """
    return await get_client().bulk_scan(csv_body)


@mcp.tool()
async def bulk_progress(batch_id: str) -> dict[str, Any]:
    """Progress for a bulk batch: totals and per-status counts."""
    return await get_client().bulk_progress(batch_id)


@mcp.tool()
async def submit_feedback(
    scan_id: str,
    finding_kind: str,
    verdict: str,
    signature_name: str | None = None,
    comment: str | None = None,
) -> dict[str, Any]:
    """Record a finding verdict (correct / false_positive) for a scan.

    Args:
        finding_kind: One of auth, security, antibot, captcha, waf, fingerprinting.
        verdict: One of correct, false_positive.
        signature_name: Optional detector/signature the verdict applies to.
    """
    return await get_client().submit_feedback(
        scan_id,
        finding_kind=finding_kind,
        verdict=verdict,
        signature_name=signature_name,
        comment=comment,
    )


@mcp.tool()
async def feedback_stats() -> list[dict[str, Any]]:
    """Confirmation / false-positive rates per signature."""
    return await get_client().feedback_stats()


# -- transports ------------------------------------------------------------


class BearerTokenGuard:
    """Pure-ASGI bearer gate so streaming responses are not buffered."""

    def __init__(self, app: Any, token: str) -> None:
        self.app = app
        self.token = token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        expected = f"Bearer {self.token}"
        if not hmac.compare_digest(headers.get("authorization", ""), expected):
            response = JSONResponse({"detail": "unauthorized"}, status_code=401)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


def _is_loopback(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


def run_http(transport: str, host: str, port: int, token: str | None, allow_remote: bool) -> None:
    import uvicorn

    if not _is_loopback(host) and not allow_remote:
        raise SystemExit(f"refusing to bind {host!r}: pass --allow-remote to expose the server")
    if allow_remote and not token:
        raise SystemExit("--allow-remote requires AUTHSCOPE_MCP_TOKEN or --token")
    app = mcp.sse_app() if transport == "sse" else mcp.streamable_http_app()
    guarded = BearerTokenGuard(app, token) if token else app
    uvicorn.run(guarded, host=host, port=port, log_level="info")


def main(argv: list[str] | None = None) -> None:
    import os

    parser = argparse.ArgumentParser(
        prog="authscope-mcp", description="AuthScope MCP server (stdio / http / sse)"
    )
    parser.add_argument("--transport", choices=["stdio", "http", "sse"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_HTTP_PORT)
    parser.add_argument("--token", default=os.environ.get("AUTHSCOPE_MCP_TOKEN"))
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="permit binding a non-loopback host (requires a bearer token)",
    )
    args = parser.parse_args(argv)

    if args.transport == "stdio":
        mcp.run("stdio")
    else:
        run_http(args.transport, args.host, args.port, args.token, args.allow_remote)


if __name__ == "__main__":  # pragma: no cover
    main()
