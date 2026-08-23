"""Load test harness for the scan-enqueue path and full pipeline.

Usage:
  python scripts/loadtest.py --url http://localhost:8000 --key <api-key> \
      [--target https://example.com/login] [--total 200] [--concurrency 20] \
      [--real-scans]   # actually execute scans (needs running celery workers)
"""

from __future__ import annotations

import argparse
import asyncio
import time

import httpx


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--key", required=True)
    parser.add_argument("--target", default="https://example.com/login")
    parser.add_argument("--total", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--rate-limit-bypass", action="store_true",
                        help="use unique keys? not supported; raise key limit instead")
    args = parser.parse_args()

    latencies: list[float] = []
    errors = 0
    semaphore = asyncio.Semaphore(args.concurrency)

    async def one(client: httpx.AsyncClient, i: int) -> None:
        nonlocal errors
        async with semaphore:
            start = time.monotonic()
            try:
                resp = await client.post(
                    "/v1/scans",
                    json={"url": f"{args.target}?i={i}", "options": {"force": True}},
                    headers={"X-API-Key": args.key},
                )
                if resp.status_code != 202:
                    errors += 1
                else:
                    scan_id = resp.json()["scan_id"]
                    # poll until finished (only meaningful with real workers)
                    for _ in range(120):
                        r = await client.get(f"/v1/scans/{scan_id}",
                                             headers={"X-API-Key": args.key})
                        status = r.json().get("status")
                        if status not in ("queued", "running"):
                            break
                        await asyncio.sleep(1.0)
            except Exception:  # noqa: BLE001
                errors += 1
            finally:
                latencies.append(time.monotonic() - start)

    async with httpx.AsyncClient(base_url=args.base_url, timeout=180) as client:
        health = await client.get("/healthz")
        assert health.status_code == 200, "API unhealthy"
        started = time.monotonic()
        await asyncio.gather(*(one(client, i) for i in range(args.total)))
        wall = time.monotonic() - started

    latencies.sort()
    n = len(latencies) or 1

    def pct(p: float) -> float:
        return latencies[min(int(p * n), n - 1)]

    print(f"requests={n} errors={errors} wall={wall:.1f}s "
          f"throughput={n / wall:.1f}/s")
    print(f"latency p50={pct(0.5):.2f}s p95={pct(0.95):.2f}s p99={pct(0.99):.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
