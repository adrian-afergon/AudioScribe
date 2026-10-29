"""PLAN-02 slices 1-2: authenticated registration, bounded staging receipt."""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import time
from pathlib import Path

import pytest

from audioscribe.config import Config
from audioscribe.service import Scanner
from audioscribe.store import Store
from audioscribe.upload.auth import generate_secret_offline
from audioscribe.upload.http import UploadRuntime, make_upload_app
from audioscribe.upload.resources import DiskReservations

FIXTURE_ROOT = Path(__import__("os").environ.get(
    "AUDIOSCRIBE_LQ04_FIXTURE_ROOT",
    "/tmp/opencode/audioscribe-plan01.dJebPg/lq04-fixtures/C-LQ04-BOOTSTRAP-01"))

pytestmark = pytest.mark.skipif(
    not FIXTURE_ROOT.is_dir(),
    reason="LQ04 fixtures are not available; run the qualification bootstrap")

ORIGIN = "https://audioscribe.example.ts.net"


class Client:
    """Minimal ASGI driver: no socket, real application callable."""

    def __init__(self, app: object, host: str = "audioscribe.example.ts.net"):
        self.app, self.host = app, host
        self.cookie = ""
        self.csrf = ""

    def _headers(self, extra=None, auth=True, csrf=True, origin=ORIGIN, host=None):
        headers = [(b"host", (host or self.host).encode())]
        if origin is not None:
            headers.append((b"origin", origin.encode()))
        if auth and self.cookie:
            headers.append((b"cookie", self.cookie.encode()))
        if csrf and self.csrf:
            headers.append((b"x-csrf-token", self.csrf.encode()))
        headers.extend(extra or [])
        return headers

    async def _call(self, method, path, headers, body=b"", trigger=None):
        received_body = bytearray()
        sent = []

        async def receive():
            if body or received_body:
                payload = bytes(body) if body else b""
                if payload:
                    received_body.extend(payload)
                    return {"type": "http.request", "body": payload, "more_body": False}
                return {"type": "http.request", "body": b"", "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)
            if trigger and message["type"] == "http.response.start":
                trigger()
            if message["type"] == "http.response.body" and message.get("more_body", False):
                raise _StopAfterStart()

        scope = {"type": "http", "method": method, "path": path, "headers": headers,
                 "query_string": b"", "server": (self.host, 443), "scheme": "https"}
        try:
            await self.app(scope, receive, send)
        except _StopAfterStart:
            pass
        status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
        response_headers = {}
        for name, value in next((m["headers"] for m in sent
                                 if m["type"] == "http.response.start"), []):
            response_headers.setdefault(name.decode().lower(), []).append(value.decode())
        chunks = [m.get("body", b"") for m in sent if m["type"] == "http.response.body"]
        return status, response_headers, b"".join(chunks)

    def request(self, method, path, *, json_body=None, headers=None, body=b"",
                auth=True, csrf=True, origin=ORIGIN, host=None, trigger=None):
        extra = list(headers or [])
        if json_body is not None:
            body = json.dumps(json_body).encode()
            extra.append((b"content-type", b"application/json"))
        loop = asyncio.new_event_loop()
        try:
            status, response_headers, payload = loop.run_until_complete(
                self.arequest(method, path, json_body=json_body, headers=headers,
                              body=body, auth=auth, csrf=csrf, origin=origin,
                              host=host, trigger=trigger))
        finally:
            loop.close()
        return status, response_headers, payload

    async def arequest(self, method, path, *, json_body=None, headers=None, body=b"",
                       auth=True, csrf=True, origin=ORIGIN, host=None, trigger=None):
        extra = list(headers or [])
        if json_body is not None:
            body = json.dumps(json_body).encode()
            extra.append((b"content-type", b"application/json"))
        status, response_headers, payload = await self._call(
            method, path, self._headers(extra, auth=auth, csrf=csrf,
                                        origin=origin, host=host),
            body=body, trigger=trigger)
        for cookie in response_headers.get("set-cookie", []):
            if cookie.startswith("__Host-audioscribe="):
                self.cookie = cookie.split(";", 1)[0]
        payload_json = json.loads(payload) if payload.startswith(b"{") else None
        return status, response_headers, payload_json

    def login(self, secret):
        status, _, payload = self.request("GET", "/api/v1/auth/challenge", auth=False, csrf=False)
        assert status == 200 and payload["nonce"]
        status, _, payload = self.request("POST", "/api/v1/auth/login", auth=False, csrf=False,
                                          json_body={"secret": secret, "csrf": payload["nonce"]})
        assert status == 200, payload
        self.csrf = payload["csrf"]
        return payload


class OpenBodyStream:
    """One OPEN body request over the ASGI app: chunks stream while the test
    observes staging state mid-receipt, like a real XHR upload."""

    def __init__(self, client: Client, upload_id: str, token: str):
        self.client, self.upload_id, self.token = client, upload_id, token
        self.queue: asyncio.Queue = asyncio.Queue()
        self.sent: list = []
        self.task = None
        self.bytes_seen = 0

    def _scope(self):
        return {"type": "http", "method": "POST",
                "path": f"/api/v1/uploads/{self.upload_id}/body",
                "headers": self.client._headers([
                    (b"x-transfer-token", self.token.encode()),
                    (b"content-type", b"application/octet-stream")]),
                "query_string": b"", "server": (self.client.host, 443), "scheme": "https"}

    async def __aenter__(self):
        async def receive():
            return await self.queue.get()

        async def send_message(message):
            self.sent.append(message)

        self.task = asyncio.create_task(
            self.client.app(self._scope(), receive, send_message))
        await self.queue.put({"type": "http.request", "body": b"", "more_body": True})
        for _ in range(100):
            await asyncio.sleep(0)
            if any(m["type"] == "http.response.start" for m in self.sent):
                break
        return self

    async def send(self, chunk: bytes):
        self.bytes_seen += len(chunk)
        await self.queue.put({"type": "http.request", "body": chunk, "more_body": True})
        await asyncio.sleep(0)

    async def finish(self):
        await self.queue.put({"type": "http.request", "body": b"", "more_body": False})
        while not any(m["type"] in ("http.response.start", "app.error") for m in self.sent):
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)
        return self.sent

    async def abort(self):
        self.task.cancel()
        try:
            await self.task
        except (asyncio.CancelledError, Exception):
            pass

    async def __aexit__(self, exc_type, exc, tb):
        if self.task is not None and not self.task.done():
            await self.abort()
        return False


class _StopAfterStart(Exception):
    pass


def make_config(tmp_path: Path, **overrides) -> Config:
    for name in ("in", "out", "brain", "data"):
        (tmp_path / name).mkdir(exist_ok=True)
    overrides.setdefault("upload_origin", ORIGIN)
    overrides.setdefault("upload_reserve_bytes", 0)
    overrides.setdefault("stable_seconds", 1)
    overrides.setdefault("poll_seconds", 1)
    return Config(str(tmp_path / "in"), str(tmp_path / "out"), str(tmp_path / "brain"),
                  str(tmp_path / "data"), **overrides)


def make_runtime(config: Config, baseline: bool = True) -> UploadRuntime:
    from audioscribe.upload.capabilities import ensure_owned_staging
    ensure_owned_staging(Path(config.input_dir))
    runtime = UploadRuntime(config, reservations=DiskReservations(config.upload_reserve_bytes))
    runtime.start()
    if baseline:
        runtime.mark_baseline_ready()
    return runtime


def login_and_register(client: Client, config: Config, secret: str, name="clip.mp3",
                       file_bytes=None, runtime=None):
    client.login(secret)
    body = {"filename": name}
    if file_bytes is not None:
        body["file_bytes"] = file_bytes
    return client.request("POST", "/api/v1/uploads", json_body=body)


def test_authenticated_registration_reserves_slot_before_body(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    client = Client(make_upload_app(runtime))
    status, _, payload = login_and_register(client, config, secret, file_bytes=1000)
    assert status == 201, payload
    assert payload["upload_id"] and payload["transfer_token"]
    assert runtime.reservations.commitment(payload["upload_id"]) == 1000
    staged = list((Path(config.input_dir) / ".audioscribe-upload-staging").glob("*.part"))
    assert len(staged) == 1 and staged[0].stat().st_size == 0


def test_registration_rejects_wrong_origin(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    status, _, payload = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "clip.mp3"},
        origin="https://evil.example.ts.net")
    assert status == 403 and payload["error"] == "forbidden"
    assert runtime.reservations.active == 0


def test_wrong_origin_transport_rejected(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    client = Client(make_upload_app(runtime))
    status, _, payload = client.request(
        "GET", "/api/v1/auth/challenge", auth=False, csrf=False,
        origin="https://evil.example.ts.net")
    assert status == 403


def test_same_origin_gets_work_without_origin_header(tmp_path):
    """Browsers send no Origin header on same-origin GETs (fetch/XHR).

    A4: Origin is required on authentication and mutations; challenge/status
    GETs require the certified Host (and scheme), not Origin.
    """
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    client = Client(make_upload_app(runtime))
    status, _, payload = client.request(
        "GET", "/api/v1/auth/challenge", auth=False, csrf=False, origin=None)
    assert status == 200 and payload["nonce"]
    client.login(secret)
    status, _, snapshot = client.request("GET", "/api/v1/status", origin=None)
    assert status == 200 and snapshot["history"] == []
    # A wrong Origin on a GET is a cross-site request and stays rejected.
    status, _, _ = client.request(
        "GET", "/api/v1/status",
        origin="https://evil.example.ts.net")
    assert status == 403
    # A4: status requires the certified Host even without Origin.
    status, _, _ = client.request(
        "GET", "/api/v1/status", origin=None, host="evil.example.ts.net")
    assert status == 403


def test_static_routes_enforce_certified_host_scheme_and_forwarding(tmp_path):
    """A4: the page and its fixed assets are served only to the certified Host
    with a supported scheme, like every other route; forwarding chains and
    unsupported schemes fail closed."""
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    app = make_upload_app(runtime)
    client = Client(app)
    status, _, _ = client.request("GET", "/", auth=False, csrf=False, origin=None)
    assert status == 200
    status, _, _ = client.request("GET", "/", auth=False, csrf=False, origin=None,
                                  host="evil.example.ts.net")
    assert status == 403
    status, _, _ = client.request("GET", "/static/app.js", auth=False, csrf=False,
                                  origin=None, host="evil.example.ts.net")
    assert status == 403
    status, _, _ = client.request(
        "GET", "/", auth=False, csrf=False, origin=None,
        headers=[(b"x-forwarded-for", b"10.0.0.9, 100.64.0.7")])
    assert status == 403

    sent = []

    async def scenario():
        scope = {"type": "http", "method": "GET", "path": "/",
                 "headers": [(b"host", b"audioscribe.example.ts.net")],
                 "query_string": b"", "server": ("audioscribe.example.ts.net", 443),
                 "scheme": "ftp"}

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        await app(scope, receive, send)

    asyncio.run(scenario())
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    assert status == 403


def test_served_browser_flow_end_to_end(tmp_path):
    """Drives the real ASGI app with exactly the requests a browser emits.

    No Origin on same-origin GETs; Origin + X-CSRF-Token on mutations; the raw
    body XHR carries Origin, X-CSRF-Token and x-transfer-token. Every step
    must return success — never the 403s the served page used to provoke.
    """
    media = (FIXTURE_ROOT / "P2-mp3-libmp3lame.mp3").read_bytes()
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    client = Client(make_upload_app(runtime))
    status, _, _ = client.request("GET", "/", auth=False, csrf=False, origin=None)
    assert status == 200
    status, _, _ = client.request("GET", "/static/app.js", auth=False, csrf=False, origin=None)
    assert status == 200
    status, _, challenge = client.request(
        "GET", "/api/v1/auth/challenge", auth=False, csrf=False, origin=None)
    assert status == 200
    status, _, payload = client.request(
        "POST", "/api/v1/auth/login", auth=False, csrf=False,
        json_body={"secret": secret, "csrf": challenge["nonce"]})
    assert status == 200, payload
    client.csrf = payload["csrf"]
    status, _, registration = client.request(
        "POST", "/api/v1/uploads",
        json_body={"filename": "flujo.mp3", "file_bytes": len(media)})
    assert status == 201, registration
    status, _, record = client.request(
        "POST", f"/api/v1/uploads/{registration['upload_id']}/body",
        headers=[(b"x-transfer-token", registration["transfer_token"].encode()),
                 (b"content-type", b"application/octet-stream")],
        body=media)
    assert status == 200, record
    assert record["state"] == "published"
    status, _, snapshot = client.request("GET", "/api/v1/status", origin=None)
    assert status == 200
    assert any(row["upload_id"] == registration["upload_id"] for row in snapshot["history"])


def test_forwarding_chain_policy(tmp_path):
    """Single-hop proxy headers (Tailscale Serve on loopback) are tolerated
    and never used as identity; multi-hop chains and duplicated forwarding
    headers are unexpected and rejected."""
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    status, _, _ = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "a.mp3", "file_bytes": 10},
        headers=[(b"x-forwarded-for", b"100.64.0.7")])
    assert status == 201
    status, _, payload = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "b.mp3", "file_bytes": 10},
        headers=[(b"x-forwarded-for", b"10.0.0.9, 100.64.0.7")])
    assert status == 403 and payload["error"] == "forbidden"
    status, _, payload = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "c.mp3", "file_bytes": 10},
        headers=[(b"x-forwarded-for", b"100.64.0.7"),
                 (b"x-forwarded-for", b"100.64.0.8")])
    assert status == 403 and payload["error"] == "forbidden"


def test_login_disconnect_breaks_body_read(tmp_path):
    """An unauthenticated POST /auth/login whose client disconnects before the
    body must terminate promptly: uvicorn's receive() returns http.disconnect
    immediately, so a spinning reader would block the whole listener loop."""
    config = make_config(tmp_path)
    generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    app = make_upload_app(runtime)
    sent = []

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": "/api/v1/auth/login",
             "headers": [(b"host", b"audioscribe.example.ts.net"),
                         (b"origin", ORIGIN.encode())],
             "query_string": b"", "server": ("audioscribe.example.ts.net", 443),
             "scheme": "https"}

    async def scenario():
        await asyncio.wait_for(app(scope, receive, send), timeout=2)

    asyncio.run(scenario())
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    assert status == 499


def test_login_json_receive_count_is_bounded(tmp_path):
    """Zero-byte keepalive body messages must not extend the bounded JSON
    read forever: the receive count is capped and the request is rejected."""
    config = make_config(tmp_path)
    generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    app = make_upload_app(runtime)
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": True}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": "/api/v1/auth/login",
             "headers": [(b"host", b"audioscribe.example.ts.net"),
                         (b"origin", ORIGIN.encode())],
             "query_string": b"", "server": ("audioscribe.example.ts.net", 443),
             "scheme": "https"}

    async def scenario():
        await asyncio.wait_for(app(scope, receive, send), timeout=2)

    asyncio.run(scenario())
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    assert status == 422


def test_busy_has_no_waiting_queue(tmp_path):
    config = make_config(tmp_path, upload_concurrency=1)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    status, _, first = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "a.mp3", "file_bytes": 100})
    assert status == 201
    status, _, second = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "b.mp3", "file_bytes": 100})
    assert status == 409 and second["error"] == "busy"


def test_registration_timeout_without_bytes(tmp_path):
    config = make_config(tmp_path, upload_inactivity_seconds=0.05)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    status, _, payload = login_and_register(client, config, secret, file_bytes=10)
    assert status == 201
    upload_id = payload["upload_id"]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        record = runtime.transfer_record(upload_id)
        if record is not None and record.state in {"cancelled", "failed"}:
            break
        time.sleep(0.02)
    assert record.state == "cancelled"
    assert runtime.reservations.active == 0
    assert not list((Path(config.input_dir) / ".audioscribe-upload-staging").glob("*.part"))


def test_partial_body_remains_staged_and_excluded(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    store = Store(config.database)
    scanner = Scanner(config, store)
    scanner.baseline()
    runtime.mark_baseline_ready()
    client = Client(make_upload_app(runtime))
    client.login(secret)
    media = (FIXTURE_ROOT / "P2-mp3-libmp3lame.mp3").read_bytes()
    status, _, payload = client.request(
        "POST", "/api/v1/uploads",
        json_body={"filename": "partial.mp3", "file_bytes": len(media) + 100})
    assert status == 201
    token = payload["transfer_token"]
    upload_id = payload["upload_id"]
    staging = Path(config.input_dir) / ".audioscribe-upload-staging"

    async def scenario():
        async with OpenBodyStream(client, upload_id, token) as stream:
            await stream.send(media[:100])
            parts = list(staging.glob("*.part"))
            assert len(parts) == 1 and parts[0].stat().st_size == 100
            discovered = [p.name for p in scanner.paths()]
            assert all(not name.endswith(".part") for name in discovered)
            scanner.scan()
            rows = store.db.execute("SELECT path FROM files").fetchall()
            assert all(".audioscribe-upload-staging" not in row["path"] for row in rows)
            record = runtime.transfer_record(upload_id)
            assert record.state == "receiving" and record.bytes_received == 100
        return runtime.transfer_record(upload_id)

    record = asyncio.run(scenario())
    assert record.state in ("cancelled", "failed")
    assert runtime.reservations.active == 0


def test_reserved_before_expiry_body_start_requires_reauth(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    status, _, payload = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "late.mp3", "file_bytes": 100})
    assert status == 201
    upload_id, token = payload["upload_id"], payload["transfer_token"]
    runtime.expire_session_for_test(client.cookie)
    status, _, payload = client.request(
        "POST", f"/api/v1/uploads/{upload_id}/body",
        headers=[(b"x-transfer-token", token.encode())], body=b"abc")
    assert status == 401 and payload["error"] == "authentication_required"
    assert runtime.reservations.active == 0
    assert not list((Path(config.input_dir) / ".audioscribe-upload-staging").glob("*.part"))


def test_proxy_origin_csrf_and_multipart_rejected(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    status, _, _ = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "a.mp3"},
        origin="https://evil.example.ts.net")
    assert status == 403
    status, _, _ = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "a.mp3"}, csrf=False)
    assert status == 403
    status, _, _ = client.request(
        "POST", "/api/v1/uploads",
        headers=[(b"content-type", b"multipart/form-data; boundary=x")],
        body=b"--x\r\n")
    assert status == 415


def test_staging_never_discovered_after_stability(tmp_path):
    config = make_config(tmp_path, stable_seconds=0)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    store = Store(config.database)
    scanner = Scanner(config, store)
    scanner.baseline()
    runtime.mark_baseline_ready()
    client = Client(make_upload_app(runtime))
    client.login(secret)
    media = (FIXTURE_ROOT / "P2-mp3-libmp3lame.mp3").read_bytes()
    status, _, payload = client.request(
        "POST", "/api/v1/uploads",
        json_body={"filename": "idle.mp3", "file_bytes": len(media) + 50})
    token, upload_id = payload["transfer_token"], payload["upload_id"]

    async def scenario():
        async with OpenBodyStream(client, upload_id, token) as stream:
            await stream.send(media[:50])
            scanner.scan()
            time.sleep(0.01)
            scanner.scan(now=time.time() + 10_000)
            assert store.db.execute("SELECT COUNT(*) c FROM jobs").fetchone()["c"] == 0
        return runtime.transfer_record(upload_id)

    record = asyncio.run(scenario())
    assert record.state in ("cancelled", "failed")


def test_unknown_length_overflow_cleanup(tmp_path):
    config = make_config(tmp_path, upload_max_bytes=1000)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    status, _, payload = client.request("POST", "/api/v1/uploads",
                                        json_body={"filename": "big.mp3"})
    assert status == 201
    upload_id, token = payload["upload_id"], payload["transfer_token"]
    status, _, payload = client.request(
        "POST", f"/api/v1/uploads/{upload_id}/body",
        headers=[(b"x-transfer-token", token.encode())],
        body=b"x" * 1001)
    assert status == 413 and payload["error"] == "too_large"
    assert runtime.reservations.active == 0
    assert not list((Path(config.input_dir) / ".audioscribe-upload-staging").glob("*.part"))


def test_external_consumer_cancels_all_unpublished(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    status, _, payload = client.request(
        "POST", "/api/v1/uploads",
        json_body={"filename": "victim.mp3", "file_bytes": 10_000_000})
    assert status == 201
    upload_id = payload["upload_id"]
    runtime.freeze_for_external_consumption()
    record = runtime.transfer_record(upload_id)
    assert record.state == "cancelled"
    assert runtime.reservations.active == 0


def test_unowned_staging_namespace_not_hidden_or_deleted(tmp_path):
    config = make_config(tmp_path, recursive=True)
    root = Path(config.input_dir)
    staging = root / ".audioscribe-upload-staging"
    staging.mkdir()
    user_file = staging / "user-clip.mp3"
    user_file.write_bytes(b"not-empty-audio")
    from audioscribe.upload.capabilities import ensure_owned_staging
    with pytest.raises(PermissionError):
        ensure_owned_staging(root)
    store = Store(config.database)
    scanner = Scanner(config, store)
    assert user_file in scanner.paths()
    assert user_file.exists()


def test_duplicate_transfer_token_rejected(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    status, _, payload = client.request(
        "POST", "/api/v1/uploads",
        json_body={"filename": "once.mp3", "file_bytes": 16})
    upload_id, token = payload["upload_id"], payload["transfer_token"]

    async def scenario():
        async with OpenBodyStream(client, upload_id, token) as stream:
            await stream.send(b"first-write-0000")
            status, _, retry = await client.arequest(
                "POST", f"/api/v1/uploads/{upload_id}/body",
                headers=[(b"x-transfer-token", token.encode())], body=b"replay-attempt0")
            assert status == 403 and retry["error"] == "forbidden"

    asyncio.run(scenario())
    runtime.cancel_transfer(runtime.transfer_record(upload_id))
    assert runtime.reservations.active == 0


def test_framing_mismatch_rejected(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    status, _, payload = client.request(
        "POST", "/api/v1/uploads",
        json_body={"filename": "mismatch.mp3", "file_bytes": 100})
    upload_id, token = payload["upload_id"], payload["transfer_token"]
    status, _, payload = client.request(
        "POST", f"/api/v1/uploads/{upload_id}/body",
        headers=[(b"x-transfer-token", token.encode()),
                 (b"content-length", b"50")],
        body=b"x" * 100)
    assert status == 422
    assert runtime.reservations.active == 0
    assert not list((Path(config.input_dir) / ".audioscribe-upload-staging").glob("*.part"))


def test_login_rate_limit_burst_then_reject(tmp_path):
    """A4 line 75: global login token bucket 10/s, burst 20 — bounded
    counters, immediate rejection, no session churn."""
    config = make_config(tmp_path)
    generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    client = Client(make_upload_app(runtime))
    statuses = []
    for _ in range(25):
        status, _, payload = client.request(
            "POST", "/api/v1/auth/login", auth=False, csrf=False,
            json_body={"secret": "wrong-secret-wrong-secret-wrong-secret-wrong-se",
                       "csrf": "bogus"})
        statuses.append(status)
    assert statuses[:20] == [401] * 20, "the burst must be admitted to verification"
    assert statuses[20:] == [429] * 5, \
        f"beyond the burst, login attempts must be rate limited: {statuses[20:]}"
