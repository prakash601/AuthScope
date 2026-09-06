"""ISS-020 tests: bulk CSV scans."""

from __future__ import annotations

import uuid

from tests.fixtures_site import page as fx


async def test_bulk_csv_creates_batch(app_client, user_and_key):
    _, client = app_client
    csv_body = "url\nhttps://bulk-a.example.com/login\nhttps://bulk-b.example.com/signin\n"
    resp = await client.post(
        "/v1/scans/bulk",
        content=csv_body,
        headers={**user_and_key["headers"], "Content-Type": "text/csv"},
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["accepted"] == 2 and body["skipped"] == 0
    assert len(body["results"]) == 2
    assert all(r["scan_id"] for r in body["results"])
    # unique batch, unique scan ids
    ids = {r["scan_id"] for r in body["results"]}
    assert len(ids) == 2

    # rows visible with batch id in options
    session_factory = app_client[0].state.session_factory
    import sqlalchemy as sa

    from db.models import Scan

    async with session_factory() as session:
        row = (
            await session.execute(
                sa.select(Scan).where(Scan.id == uuid.UUID(body["results"][0]["scan_id"]))
            )
        ).scalar_one()
        assert row.options.get("batch_id") == body["batch_id"]
        assert row.status == "queued"


async def test_bulk_skips_malformed_rows(app_client, user_and_key):
    _, client = app_client
    csv_body = "url\nhttps://ok.example.com/l\nnot-a-url\n\n"
    resp = await client.post(
        "/v1/scans/bulk",
        content=csv_body,
        headers={**user_and_key["headers"], "Content-Type": "text/csv"},
    )
    body = resp.json()
    # 'not-a-url' has no scheme/host -> rejected; empty line ignored
    skipped_reasons = [r for r in body["results"] if r["error"]]
    assert body["accepted"] >= 1
    assert len(skipped_reasons) >= 1
    assert all(r["error"].startswith("url_rejected") for r in skipped_reasons)


async def test_bulk_rejects_over_1000(app_client, user_and_key):
    _, client = app_client
    urls = "\n".join(f"https://site{i}.example.com/l" for i in range(1001))
    csv_body = "url\n" + urls + "\n"
    resp = await client.post(
        "/v1/scans/bulk",
        content=csv_body,
        headers={**user_and_key["headers"], "Content-Type": "text/csv"},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "too_many_urls"


async def test_bulk_empty_body_400(app_client, user_and_key):
    _, client = app_client
    resp = await client.post(
        "/v1/scans/bulk",
        content="url\n",
        headers={**user_and_key["headers"], "Content-Type": "text/csv"},
    )
    assert resp.status_code == 400


async def test_bulk_accepts_bare_url_lines(app_client, user_and_key):
    """Headerless lists of URLs are also accepted."""
    _, client = app_client
    body = f"{fx('index.html')}\n{fx('honeypot.html')}\n"
    resp = await client.post(
        "/v1/scans/bulk",
        content=body,
        headers={**user_and_key["headers"], "Content-Type": "text/csv"},
    )
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 2


async def test_bulk_progress_counts(app_client, user_and_key, second_user_and_key):
    _, client = app_client
    csv_body = "url\nhttps://prog-a.example.com/l\nhttps://prog-b.example.com/l\nbad-row\n"
    created = await client.post(
        "/v1/scans/bulk",
        content=csv_body,
        headers={**user_and_key["headers"], "Content-Type": "text/csv"},
    )
    assert created.status_code == 202
    batch_id = created.json()["batch_id"]
    assert created.json()["accepted"] == 2

    progress = await client.get(f"/v1/scans/bulk/{batch_id}", headers=user_and_key["headers"])
    assert progress.status_code == 200
    body = progress.json()
    assert body["batch_id"] == batch_id and body["total"] == 2
    assert body["by_status"]["queued"] == 2

    # owner-scoped: other user sees no such batch
    other = await client.get(f"/v1/scans/bulk/{batch_id}", headers=second_user_and_key["headers"])
    assert other.status_code == 404

    unknown = await client.get("/v1/scans/bulk/no-such-batch", headers=user_and_key["headers"])
    assert unknown.status_code == 404
