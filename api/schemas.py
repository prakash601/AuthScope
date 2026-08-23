"""Shared API schemas (Pydantic v2)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScanOptions(BaseModel):
    proxy_country: str | None = None
    capture_har: bool = True
    deep_scan: bool = False
    force: bool = Field(default=False, description="bypass the result cache")


class ScanCreateRequest(BaseModel):
    url: str
    options: ScanOptions = Field(default_factory=ScanOptions)


class ScanAccepted(BaseModel):
    scan_id: str
    status: str
    cached: bool = False


class BulkScanResult(BaseModel):
    url: str
    scan_id: str | None = None
    error: str | None = None


class BulkScanAccepted(BaseModel):
    batch_id: str
    accepted: int
    skipped: int
    results: list[BulkScanResult]


class ScanSummary(BaseModel):
    scan_id: str
    url: str
    normalized_url: str
    status: str
    difficulty_score: int | None = None
    security_score: int | None = None
    created_at: str | None = None
    completed_at: str | None = None


class ScanListResponse(BaseModel):
    total: int
    items: list[ScanSummary]
