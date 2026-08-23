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
    bucket = get_settings().s3.bucket
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
        refs["screenshot_url"] = put(
            f"scans/{scan_id}/page.png", screenshot_png, "image/png"
        )
    if dom_html:
        refs["dom_snapshot_url"] = put(
            f"scans/{scan_id}/dom.html", dom_html.encode(), "text/html"
        )
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
