"""PageArtifact: the immutable evidence bundle passed to every detector.

Built from collector outputs (network interceptor, runtime hooks, static
analyzer). Serializes losslessly to JSON for persistence and for future AI
microservices that consume artifacts.

Example JSON shape (abridged):
    {
      "url": "https://example.com/login",
      "final_url": "https://example.com/login",
      "status": 200,
      "blocked": false,
      "requests": [{"url": "...", "method": "GET", "resource_type": "document", ...}],
      "cookies": [{"name": "sess", "secure": true, ...}],
      "headers": {"strict-transport-security": "max-age=..."},
      "dom": {"title": "Sign in", "forms": [...], "scripts": [...], ...},
      "globals": ["auth0Client", "..."],
      "hook_log": [{"kind": "fetch", "method": "POST", "url": "..."}],
      "fingerprint_reads": {"canvas_dataurl": 0, "canvas_imagedata": 0}
    }
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CapturedRequest(BaseModel):
    url: str
    method: str = "GET"
    resource_type: str = "other"
    status: int | None = None
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)
    is_xhr_fetch: bool = False
    started_at: float | None = None
    duration_ms: int | None = None


class CookieInfo(BaseModel):
    name: str
    value: str = ""
    domain: str = ""
    path: str = "/"
    secure: bool = False
    httponly: bool = False
    samesite: str = "Lax"
    expires: float = -1


class FormField(BaseModel):
    name: str = ""
    type: str = "text"
    autocomplete: str | None = None
    maxlength: int | None = None
    honeypot_candidate: bool = False


class FormInfo(BaseModel):
    action: str = ""
    method: str = "GET"
    fields: list[FormField] = Field(default_factory=list)


class MetaInfo(BaseModel):
    name: str = ""
    attribute: str = "name"
    content: str = ""


class DomSummary(BaseModel):
    title: str = ""
    raw_html: str = ""
    forms: list[FormInfo] = Field(default_factory=list)
    scripts: list[str] = Field(default_factory=list)
    inline_scripts: list[str] = Field(default_factory=list)
    iframes: list[str] = Field(default_factory=list)
    metas: list[MetaInfo] = Field(default_factory=list)
    body_text_sample: str = ""


class PageArtifact(BaseModel):
    url: str
    final_url: str = ""
    http_status: int | None = None
    blocked: bool = False
    blocked_reason: str | None = None
    load_duration_ms: int = 0

    requests: list[CapturedRequest] = Field(default_factory=list)
    cookies: list[CookieInfo] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)

    dom: DomSummary = Field(default_factory=DomSummary)
    globals: list[str] = Field(default_factory=list)
    hook_log: list[dict] = Field(default_factory=list)
    fingerprint_reads: dict[str, int] = Field(default_factory=dict)

    screenshot_ref: str | None = None
    har_ref: str | None = None
    trace_ref: str | None = None

    def request_urls(self) -> list[str]:
        return [r.url for r in self.requests]
