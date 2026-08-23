"""ISS-021 tests: webhook signing, retries/backoff, dead-letter queue."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from workers.webhooks import DLQ_KEY, SIGNATURE_HEADER, deliver, dispatch_report


class _Receiver(BaseHTTPRequestHandler):
    """Programmable receiver: fails the first N POSTs per path."""

    server_version = "TestReceiver/1.0"

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        with self.server.lock:
            self.server.hits[self.path] = self.server.hits.get(self.path, 0) + 1
            hits = self.server.hits[self.path]
            self.server.bodies.append((self.path, body,
                                       dict(self.headers)))
        fail_times = self.server.fail_first.get(self.path, 0)
        if hits <= fail_times:
            self.send_response(500)
        else:
            self.send_response(200)
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/dlq":
            with self.server.lock:
                n = len(self.server.bodies)
            self._send(json.dumps({"received": n}).encode())
        else:
            self._send(b"ok")

    def _send(self, body):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def receiver():
    server = ThreadingHTTPServer(("127.0.0.1", 8932), _Receiver)
    server.lock = threading.Lock()
    server.hits = {}
    server.fail_first = {"/always-fails": 999, "/flaky": 2}
    server.bodies = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


async def test_delivery_signed_and_verified(receiver):
    secret = "s3cret"
    ok, err = await deliver(f"http://127.0.0.1:8932/ok-{uuid4hex()}", secret,
                            {"hello": "world"})
    assert ok and err == ""
    path, body, headers = receiver.bodies[-1]
    sig = headers.get(SIGNATURE_HEADER)
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert sig == f"sha256={expected}"


def uuid4hex() -> str:
    import uuid

    return uuid.uuid4().hex[:8]


async def test_retry_then_success(receiver):
    url = "http://127.0.0.1:8932/flaky"
    ok, err = await deliver(url, "x", {"n": 1})
    assert ok is True  # failed twice (500) then succeeded on attempt 3
    assert receiver.hits["/flaky"] == 3


async def test_persistent_failure_dead_letters(app_client, receiver):
    app, _client = app_client
    redis = app.state.redis
    await redis.delete(DLQ_KEY)
    url = "http://127.0.0.1:8932/always-fails"
    statuses = await dispatch_report(redis, [(url, "secret")],
                                     {"report": True}, "scan-1")
    assert statuses[url].startswith("failed:")
    assert receiver.hits["/always-fails"] >= 3  # retried with backoff

    dlq_len = await redis.llen(DLQ_KEY)
    entry = json.loads(await redis.lindex(DLQ_KEY, dlq_len - 1))
    assert entry["url"] == url and entry["scan_id"] == "scan-1"
    assert "dead_lettered_at" in entry


async def test_webhook_crud_endpoints(app_client, user_and_key):
    _, client = app_client
    headers = user_and_key["headers"]

    created = await client.post("/v1/webhooks", json={"url": "https://hooks.example/x"},
                                headers=headers)
    assert created.status_code == 201
    body = created.json()
    wid = body["id"]
    assert body["secret"] and body["active"] is True

    listing = await client.get("/v1/webhooks", headers=headers)
    assert any(w["id"] == wid for w in listing.json())

    deleted = await client.delete(f"/v1/webhooks/{wid}", headers=headers)
    assert deleted.status_code == 204

    gone = await client.delete(f"/v1/webhooks/{wid}", headers=headers)
    assert gone.status_code == 404

    other_owner = await client.delete(
        f"/v1/webhooks/{uuid4hex()}", headers={**headers, "X-API-Key": headers["X-API-Key"]}
    )
    assert other_owner.status_code == 404
