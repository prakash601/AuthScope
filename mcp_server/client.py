"""Async HTTP client for the AuthScope public API.

Thin, dependency-light wrapper over ``/v1/*`` used by the MCP tools. Reads
``AUTHSCOPE_API_URL`` (default ``http://localhost:8000``) and
``AUTHSCOPE_API_KEY`` from the environment. The API key is never logged and
never echoed back in tool output.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

DEFAULT_API_URL = "http://localhost:8000"

# Scan statuses that will not change again. ``waf_blocked`` still has a report.
TERMINAL_STATUSES = frozenset({"completed", "failed", "waf_blocked"})


class AuthScopeError(RuntimeError):
    """AuthScope API returned an error, or could not be reached."""

    def __init__(self, message: str, *, code: str = "error", status: int | None = None):
        super().__init__(message)
        self.code = code
        self.status = status


class AuthScopeClient:
    """Small async client over the AuthScope API."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        resolved = base_url or os.environ.get("AUTHSCOPE_API_URL") or DEFAULT_API_URL
        self.base_url = resolved.rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("AUTHSCOPE_API_KEY")
        self.timeout = timeout
        self._transport = transport

    # -- internals ---------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        if not self.api_key:
            raise AuthScopeError(
                "AUTHSCOPE_API_KEY is not set",
                code="missing_api_key",
            )
        return {"X-API-Key": self.api_key}

    def _client(self) -> httpx.AsyncClient:
        kwargs: dict[str, Any] = {"base_url": self.base_url, "timeout": self.timeout}
        if self._transport is not None:
            kwargs["transport"] = self._transport
        return httpx.AsyncClient(**kwargs)

    @staticmethod
    def _error(resp: httpx.Response) -> AuthScopeError:
        code = "http_error"
        message = resp.text[:300]
        try:
            detail = resp.json().get("detail")
            if isinstance(detail, dict):
                code = detail.get("code", code)
                message = detail.get("message", message)
            elif isinstance(detail, str):
                message = detail
        except ValueError:  # non-JSON body
            pass
        hint = {
            401: " Check AUTHSCOPE_API_KEY (missing or inactive).",
            404: " Scan/batch not found or not owned by this API key.",
            422: " Invalid request payload.",
        }.get(resp.status_code, "")
        if resp.status_code == 429:
            retry = resp.headers.get("Retry-After", "?")
            hint = f" Rate limited; retry after {retry}s."
        return AuthScopeError(f"{message}{hint}", code=code, status=resp.status_code)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> Any:
        merged = {**self._headers(), **(headers or {})}
        try:
            async with self._client() as client:
                resp = await client.request(method, path, headers=merged, **kwargs)
        except httpx.HTTPError as exc:
            raise AuthScopeError(
                f"AuthScope API unreachable at {self.base_url}: {exc}",
                code="unreachable",
            ) from exc
        if resp.status_code >= 400:
            raise self._error(resp)
        if resp.status_code == 204 or not resp.content:
            return {}
        return resp.json()

    # -- endpoints ---------------------------------------------------------

    async def health(self) -> dict[str, Any]:
        """Report API reachability and whether the configured key is accepted."""
        out: dict[str, Any] = {"api_url": self.base_url}
        try:
            async with self._client() as client:
                resp = await client.get("/healthz")
            out["service"] = (
                resp.json() if resp.status_code < 400 else {"status": f"http_{resp.status_code}"}
            )
        except httpx.HTTPError as exc:
            out["service"] = {"status": "unreachable", "error": str(exc)}
            out["auth"] = "unchecked"
            return out
        if not self.api_key:
            out["auth"] = "missing_api_key"
            return out
        try:
            await self.list_scans(limit=1)
            out["auth"] = "ok"
        except AuthScopeError as exc:
            out["auth"] = f"error:{exc.code}"
        return out

    async def create_scan(
        self,
        url: str,
        *,
        proxy_country: str | None = None,
        deep_scan: bool = False,
        force: bool = False,
        capture_har: bool = True,
    ) -> dict[str, Any]:
        options: dict[str, Any] = {
            "deep_scan": deep_scan,
            "force": force,
            "capture_har": capture_har,
        }
        if proxy_country:
            options["proxy_country"] = proxy_country
        return await self._request("POST", "/v1/scans", json={"url": url, "options": options})

    async def get_scan(self, scan_id: str) -> dict[str, Any]:
        return await self._request("GET", f"/v1/scans/{scan_id}")

    async def list_scans(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        provider: str | None = None,
        captcha_type: str | None = None,
        waf_provider: str | None = None,
        min_difficulty: int | None = None,
        max_difficulty: int | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        for key, value in {
            "provider": provider,
            "captcha_type": captcha_type,
            "waf_provider": waf_provider,
            "min_difficulty": min_difficulty,
            "max_difficulty": max_difficulty,
            "status": status,
        }.items():
            if value is not None:
                params[key] = value
        return await self._request("GET", "/v1/scans", params=params)

    async def get_diff(self, scan_id: str, *, days: int = 30) -> dict[str, Any]:
        return await self._request("GET", f"/v1/scans/{scan_id}/diff", params={"days": days})

    async def bulk_scan(self, csv_body: str) -> dict[str, Any]:
        """Submit a CSV with a ``url`` column header (or bare URL lines)."""
        return await self._request(
            "POST",
            "/v1/scans/bulk",
            content=csv_body.encode("utf-8"),
            headers={"Content-Type": "text/csv"},
        )

    async def bulk_progress(self, batch_id: str) -> dict[str, Any]:
        return await self._request("GET", f"/v1/scans/bulk/{batch_id}")

    async def submit_feedback(
        self,
        scan_id: str,
        *,
        finding_kind: str,
        verdict: str,
        signature_name: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/v1/scans/{scan_id}/feedback",
            json={
                "finding_kind": finding_kind,
                "verdict": verdict,
                "signature_name": signature_name,
                "comment": comment,
            },
        )

    async def feedback_stats(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/v1/feedback/stats")
