"""ISS-023 tests: evidence service — presigned URLs and retention cleanup."""

from __future__ import annotations

import uuid

import httpx
import pytest

from config import get_settings
from pipeline.evidence import (
    cleanup_expired,
    download,
    make_client,
    presign_url,
    upload_evidence,
)


def _client():
    return make_client()


def _bucket() -> str:
    return get_settings().s3.bucket


def _minio_up() -> bool:
    try:
        _client().head_bucket(Bucket=_bucket())
        return True
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(not _minio_up(), reason="MinIO not reachable")


async def test_presigned_url_allows_get_and_expires():
    scan_id = f"presign-test-{uuid.uuid4().hex[:8]}"
    refs = upload_evidence(scan_id, har_json='{"k": "v"}', client=_client())
    try:
        signed = presign_url(refs["har_url"], expires_seconds=60)
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.get(signed)
        assert resp.status_code == 200
        assert json_loads(resp.content)["k"] == "v"
    finally:
        _delete(scan_id)


async def test_unsigned_access_is_denied():
    scan_id = f"private-test-{uuid.uuid4().hex[:8]}"
    refs = upload_evidence(scan_id, har_json="secret", client=_client())
    try:
        bucket, key = refs["har_url"].removeprefix("s3://").partition("/")[::2]
        base = get_settings().s3.endpoint_url
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.get(f"{base}/{bucket}/{key}")
        assert resp.status_code == 403
    finally:
        _delete(scan_id)


async def test_cleanup_expired_deletes_old_objects():
    scan_id = f"cleanup-test-{uuid.uuid4().hex[:8]}"
    upload_evidence(scan_id, har_json="old", screenshot_png=b"\x89PNG", client=_client())
    deleted = cleanup_expired(retention_days=0, prefix=f"scans/{scan_id}/", client=_client())
    assert deleted == 2
    from botocore.exceptions import ClientError

    with pytest.raises(ClientError):
        download(_client(), f"s3://{_bucket()}/scans/{scan_id}/har.json")


def _delete(scan_id: str) -> None:
    c = _client()
    paginator = c.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=_bucket(), Prefix=f"scans/{scan_id}/"):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            c.delete_objects(Bucket=_bucket(), Delete={"Objects": objs})


def json_loads(data: bytes) -> dict:
    import json

    return json.loads(data)
