"""Evidence storage: HAR / screenshot / DOM snapshot / trace → S3 or MinIO.

Minimal uploader for the pipeline; signed-URL download service and retention
cleanup are formalized in ISS-023. Object references are stored as
``s3://<bucket>/<key>`` URIs.
"""

from __future__ import annotations

import logging

import boto3

from config import get_settings

logger = logging.getLogger("authscope.evidence")


def make_client():
    s = get_settings().s3
    return boto3.client(
        "s3",
        endpoint_url=s.endpoint_url,
        aws_access_key_id=s.access_key,
        aws_secret_access_key=s.secret_key,
        region_name=s.region,
    )


def ensure_bucket(client=None, bucket: str | None = None) -> str:
    """Create the evidence bucket if missing (idempotent).

    Workers must not hard-depend on out-of-band provisioning: a fresh
    MinIO/S3 target or a deleted bucket would otherwise fail every scan
    at upload time with NoSuchBucket.
    """
    from botocore.exceptions import ClientError

    c = client or make_client()
    settings = get_settings().s3
    name = bucket or settings.bucket
    try:
        c.head_bucket(Bucket=name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in ("404", "NoSuchBucket", "NotFound"):
            raise
        kwargs: dict = {"Bucket": name}
        if settings.region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": settings.region}
        c.create_bucket(**kwargs)
        logger.info("created evidence bucket %s", name)
    return name


def upload_evidence(
    scan_id: str,
    har_json: str | None = None,
    screenshot_png: bytes | None = None,
    dom_html: str | None = None,
    trace_zip: bytes | None = None,
    client=None,
) -> dict[str, str | None]:
    """Upload available artifacts; returns s3:// URIs (None when input missing)."""
    c = client or make_client()
    bucket = ensure_bucket(c, get_settings().s3.bucket)
    refs: dict[str, str | None] = {
        "har_url": None,
        "screenshot_url": None,
        "dom_snapshot_url": None,
        "trace_url": None,
    }

    def put(key: str, body: bytes, content_type: str) -> str:
        c.put_object(Bucket=bucket, Key=key, Body=body, ContentType=content_type)
        return f"s3://{bucket}/{key}"

    if har_json:
        refs["har_url"] = put(f"scans/{scan_id}/har.json", har_json.encode(), "application/json")
    if screenshot_png:
        refs["screenshot_url"] = put(f"scans/{scan_id}/page.png", screenshot_png, "image/png")
    if dom_html:
        refs["dom_snapshot_url"] = put(f"scans/{scan_id}/dom.html", dom_html.encode(), "text/html")
    if trace_zip:
        refs["trace_url"] = put(f"scans/{scan_id}/trace.zip", trace_zip, "application/zip")
    n_uploaded = sum(v is not None for v in refs.values())
    logger.info("uploaded %d evidence objects for scan %s", n_uploaded, scan_id)
    return refs


def parse_s3_uri(uri: str) -> tuple[str, str]:
    without = uri.removeprefix("s3://")
    bucket, _, key = without.partition("/")
    return bucket, key


def download(client, uri: str) -> bytes:
    bucket, key = parse_s3_uri(uri)
    obj = client.get_object(Bucket=bucket, Key=key)
    return obj["Body"].read()


def presign_url(uri: str, expires_seconds: int | None = None, client=None) -> str:
    """Short-lived signed HTTPS GET URL for a stored s3:// reference."""
    settings = get_settings().evidence
    expires = expires_seconds or settings.presign_expires_seconds
    c = client or make_client()
    bucket, key = parse_s3_uri(uri)
    return c.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=expires,
    )


def cleanup_expired(retention_days: int | None = None, prefix: str = "scans/", client=None) -> int:
    """Delete artifacts older than the retention window. Returns deleted count."""
    import datetime as dt

    days = retention_days if retention_days is not None else get_settings().evidence.retention_days
    cutoff = dt.datetime.now(dt.UTC) - dt.timedelta(days=days)
    c = client or make_client()
    bucket = get_settings().s3.bucket
    paginator = c.get_paginator("list_objects_v2")
    to_delete: list[dict] = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            if obj["LastModified"] < cutoff:
                to_delete.append({"Key": obj["Key"]})
    for i in range(0, len(to_delete), 1000):
        chunk = to_delete[i : i + 1000]
        c.delete_objects(Bucket=bucket, Delete={"Objects": chunk})
    if to_delete:
        logger.info("evidence cleanup removed %d objects (>%dd old)", len(to_delete), days)
    return len(to_delete)
