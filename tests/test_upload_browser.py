"""PLAN-04 slices 3-4: the browser upload page contract.

The page is a single self-contained HTML document with vanilla JS served by
the existing listener. Tests cover the served contract — asset routes,
security headers, endpoint shapes and polling semantics over real HTTP — plus
the declared behaviors of the served script (transient queue, manual retry,
1-second non-overlapping polls, stale/expiry handling). No browser harness and
no framework: the JS logic is exercised through the contract it must serve.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from audioscribe.store import Store
from audioscribe.upload.auth import generate_secret_offline
from audioscribe.upload.http import make_upload_app
from audioscribe.upload.persistence import UploadStore
from test_upload_http import FIXTURE_ROOT, Client, OpenBodyStream, ORIGIN, make_config, make_runtime
from test_upload_validation import publish_through_http

import pytest

pytestmark = pytest.mark.skipif(
    not FIXTURE_ROOT.is_dir(),
    reason="LQ04 fixtures are not available; run the qualification bootstrap")

PAGE_HEADERS = {
    "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self';"
                               " connect-src 'self'; img-src 'self'; frame-ancestors 'none'",
}


def browser_runtime(config):
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    runtime.persistor = UploadStore(config.database)
    runtime.restore_persisted_state()
    return runtime, secret


def raw_get(app, path):
    """One raw GET over the ASGI app, returning undecoded body bytes."""
    loop = asyncio.new_event_loop()
    try:
        sent = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        scope = {"type": "http", "method": "GET", "path": path,
                 "headers": [(b"host", b"audioscribe.example.ts.net")],
                 "query_string": b"", "server": ("audioscribe.example.ts.net", 443),
                 "scheme": "https"}
        loop.run_until_complete(app(scope, receive, send))
        status = next(m["status"] for m in sent if m["type"] == "http.response.start")
        headers = {}
        for name, value in next((m["headers"] for m in sent
                                 if m["type"] == "http.response.start"), []):
            headers.setdefault(name.decode().lower(), []).append(value.decode())
        body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
        return status, headers, body
    finally:
        loop.close()


def get(page_client, path):
    return raw_get(page_client.app, path)


def test_static_assets_security_headers(tmp_path):
    config = make_config(tmp_path)
    runtime, _secret = browser_runtime(config)
    client = Client(make_upload_app(runtime))
    status, headers, body = get(client, "/")
    assert status == 200
    assert headers["content-type"][0].startswith("text/html")
    assert headers["x-content-type-options"] == ["nosniff"]
    assert headers["cache-control"] == ["no-store"]
    for header, expected in PAGE_HEADERS.items():
        assert headers[header] == [expected], f"page must send {header}: {expected}"
    html = body.decode("utf-8")
    # No inline script: every script tag points at packaged same-origin assets.
    for match in re.findall(r"<script\b[^>]*>", html):
        assert 'src="/static/' in match, f"inline or external script tag: {match}"
    assert 'href="/static/app.css"' in html
    assert 'type="file"' in html and "multiple" in html
    assert re.search(r'id="logout"', html)

    for name, content_type in (("app.js", "text/javascript"), ("app.css", "text/css")):
        status, headers, body = get(client, f"/static/{name}")
        assert status == 200, f"{name} must be served"
        assert headers["content-type"][0].startswith(content_type)
        assert headers["x-content-type-options"] == ["nosniff"]
        assert headers["cache-control"] == ["no-store"]
        assert headers["content-security-policy"] == ["default-src 'none'"], name
        assert headers["frame-ancestors"] == ["'none'"]
        assert body

    # Fixed allowlist only: no traversal, no arbitrary files, no media route.
    for path in ("/static/app.mjs", "/static/index.html", "/static/../../src/audioscribe/upload/http.py",
                 "/media.mp3", "/static/"):
        status, _, _ = get(client, path)
        assert status == 404, f"{path} must not be served"


def test_page_script_declares_the_upload_contract(tmp_path):
    config = make_config(tmp_path)
    runtime, _secret = browser_runtime(config)
    client = Client(make_upload_app(runtime))
    status, _, script = get(client, "/static/app.js")
    assert status == 200
    source = script.decode("utf-8")
    for endpoint in ("/api/v1/auth/challenge", "/api/v1/auth/login", "/api/v1/auth/logout",
                     "/api/v1/uploads", "/api/v1/status"):
        assert endpoint in source, f"the page must drive {endpoint}"
    # One-second polling, never overlapping, never a media download route.
    assert "POLL_INTERVAL_MS = 1000" in source
    assert "pollInFlight" in source
    # Raw Blob upload through XMLHttpRequest with the transfer token header.
    assert "XMLHttpRequest" in source and "x-transfer-token" in source
    assert "upload.onprogress" in source or "xhr.upload.addEventListener" in source
    assert "application/octet-stream" in source
    # The File object is streamed directly; no whole-file materialization.
    assert "arrayBuffer" not in source and "FileReader" not in source and "readAsArrayBuffer" not in source
    # Continuity proof stays in page memory only — never in browser storage,
    # never in a URL.
    for forbidden in ("localStorage", "sessionStorage", "indexedDB"):
        assert forbidden not in source, f"continuity proof must never reach {forbidden}"
    assert "document.cookie" not in source
    # Distinct upload lifecycle vs downstream processing states.
    for upload_state in ("queued", "starting", "streaming", "published", "rejected",
                         "cancelled"):
        assert upload_state in source, f"upload lifecycle state {upload_state} missing"
    for downstream_state in ("awaiting_scanner", "queued", "processing", "completed",
                             "error", "reused"):
        assert downstream_state in source, f"downstream state {downstream_state} missing"
    # History is rendered from the shared latest-300 view.
    assert re.search(r"history", source)
    # Manual retry only: a named handler invoked from a click binding, and no
    # timer-driven re-registration.
    assert re.search(r"manualRetry", source)
    assert not re.search(r"setInterval\s*\(", source), "polling must not overlap via setInterval"
    assert "textContent" in source, "user-derived strings must be rendered as text"
    assert not re.search(r"innerHTML", source), "unescaped HTML insertion is forbidden"
    # No external/CDN references anywhere on the page.
    status, _, html = get(client, "/")
    page = html.decode("utf-8")
    assert not re.search(r"(src|href)=\"https?://", page), "no external assets"


def test_browser_raw_blob_and_separate_status(tmp_path):
    config = make_config(tmp_path)
    runtime, secret = browser_runtime(config)
    client = Client(make_upload_app(runtime))
    media = (FIXTURE_ROOT / "P2-mp3-libmp3lame.mp3").read_bytes()

    # The exact request sequence the page performs for one file.
    status, _, challenge = client.request("GET", "/api/v1/auth/challenge", auth=False, csrf=False)
    assert status == 200
    status, _, payload = client.request(
        "POST", "/api/v1/auth/login", auth=False, csrf=False,
        json_body={"secret": secret, "csrf": challenge["nonce"]})
    assert status == 200
    assert payload["continuity_proof"] and payload["csrf"]
    client.csrf = payload["csrf"]

    status, _, registration = client.request(
        "POST", "/api/v1/uploads",
        json_body={"filename": "grabacion.mp3", "file_bytes": len(media)})
    assert status == 201, registration
    upload_id, token = registration["upload_id"], registration["transfer_token"]

    async def raw_blob():
        scope = {"type": "http", "method": "POST",
                 "path": f"/api/v1/uploads/{upload_id}/body",
                 "headers": client._headers([
                     (b"x-transfer-token", token.encode()),
                     (b"content-type", b"application/octet-stream")]),
                 "query_string": b"", "server": (client.host, 443), "scheme": "https"}

        async def receive():
            return {"type": "http.request", "body": media, "more_body": False}

        sent = []

        async def send(message):
            sent.append(message)

        await client.app(scope, receive, send)
        status = next(m["status"] for m in sent if m["type"] == "http.response.start")
        body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
        return status, json.loads(body)

    status, record = asyncio.run(raw_blob())
    assert status == 200, record
    assert record["state"] == "published"
    assert record["bytes_received"] == len(media)
    assert Path(record["published_path"]).exists()

    # Upload lifecycle and downstream processing are separate channels: the
    # body response closes the upload lifecycle while downstream is still
    # unprocessed, and only polling reveals the later transcription state.
    status, _, payload = client.request("GET", "/api/v1/status")
    row = next(r for r in payload["history"] if r["upload_id"] == upload_id)
    assert row["outcome"] == "published"
    assert row["downstream"] in (None, "awaiting_scanner")
    assert payload["concurrency"] == config.upload_concurrency
    assert payload["fresh"] is True


def function_source(source: str, name: str) -> str:
    match = re.search(rf"function {name}\(", source)
    assert match, f"the served script must define {name}"
    depth = 0
    body = source[match.start():]
    for index, character in enumerate(body):
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return body[:index + 1]
    raise AssertionError(f"unbalanced braces in {name}")


def test_transient_queue_concurrency_manual_retry(tmp_path):
    config = make_config(tmp_path, upload_concurrency=1)
    runtime, secret = browser_runtime(config)
    app = make_upload_app(runtime)
    client = Client(app)
    media = (FIXTURE_ROOT / "P2-mp3-libmp3lame.mp3").read_bytes()

    # The first transfer occupies the only admission slot.
    client.login(secret)
    status, _, active = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "a.mp3", "file_bytes": len(media)})
    assert status == 201
    # Excess admission is rejected immediately; the server has no backlog.
    status, _, busy = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "b.mp3", "file_bytes": 10})
    assert status == 409 and busy["error"] == "busy"

    # After a confirmed release, the queued file starts under a new identity.
    status, _, _ = client.request("POST", f"/api/v1/uploads/{active['upload_id']}/cancel",
                                  json_body={})
    assert status == 200
    status, _, retried = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "b.mp3", "file_bytes": 10})
    assert status == 201, retried
    assert retried["upload_id"] != active["upload_id"], "retry starts a fresh upload"

    # Page contract: transient local queue bounded by confirmed starts, and
    # retry is manual only.
    status, _, script = get(client, "/static/app.js")
    source = script.decode("utf-8")
    pump_body = function_source(source, "pump")
    assert "view.activeStarts < view.concurrency" in pump_body
    assert source.count('apiRequest("/api/v1/uploads",') == 1, \
        "only the queue pump registers uploads"
    assert source.count("manualRetry(") == 2, \
        "retry must be reachable only through the button binding"
    onfiles_body = function_source(source, "onFilesChosen")
    assert "pump()" in onfiles_body


def test_poll_failure_never_restarts(tmp_path):
    config = make_config(tmp_path)
    runtime, secret = browser_runtime(config)
    client = Client(make_upload_app(runtime))
    media = (FIXTURE_ROOT / "P2-mp3-libmp3lame.mp3").read_bytes()
    client.login(secret)
    status, record = publish_through_http(runtime, client, media, secret=secret)
    assert status == 200

    # A failing poll marks the shared view stale but never blocks authorized
    # transfers: an in-flight body completes while status is unavailable.
    config.database.chmod(0o000)
    try:
        status, _, payload = client.request("GET", "/api/v1/status")
        assert status == 503 and payload["error"] == "busy" and payload["stale"] is True
    finally:
        config.database.chmod(0o600)
    status, _, _ = client.request("POST", "/api/v1/uploads",
                                  json_body={"filename": "later.mp3", "file_bytes": 10})
    assert status == 201, "an ordinary failed poll freezes no next action"
    status, _, payload = client.request("GET", "/api/v1/status")
    assert status == 200 and payload["fresh"] is True

    # Page contract: poll failures mark stale only — no restart, no reauth,
    # no automatic retry — and they never overlap the next tick.
    status, _, script = get(client, "/static/app.js")
    source = script.decode("utf-8")
    poll_body = function_source(source, "pollNow")
    assert "view.stale = true" in poll_body
    assert "pump(" not in poll_body and "startNext(" not in poll_body
    assert "manualRetry(" not in poll_body
    assert "freezeForReauthentication" not in poll_body.split("view.stale = true")[0].split(
        "catch (transportError)")[0], "transport failures must not force reauthentication"


def test_expiry_freezes_queue_actions(tmp_path):
    config = make_config(tmp_path)
    runtime, secret = browser_runtime(config)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    media = (FIXTURE_ROOT / "P2-mp3-libmp3lame.mp3").read_bytes()
    status, _, active = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "due.mp3", "file_bytes": len(media)})
    assert status == 201
    token = active["transfer_token"]

    async def finish_authorized():
        stream = OpenBodyStream(client, active["upload_id"], token)
        await stream.__aenter__()
        await stream.send(media)
        # Natural expiry happens after body authorization: the already
        # authorized transfer still finishes.
        runtime.expire_session_for_test(client.cookie)
        await stream.send(b"")
        sent = await stream.finish()
        return next(m["status"] for m in sent if m["type"] == "http.response.start")

    assert asyncio.run(finish_authorized()) == 200, \
        "an already authorized transfer finishes despite expiry"

    # Every later browser action needs reauthentication.
    for method, path, body in (
            ("POST", "/api/v1/uploads", {"filename": "next.mp3", "file_bytes": 1}),
            ("POST", f"/api/v1/uploads/{active['upload_id']}/cancel", {}),
            ("POST", "/api/v1/auth/logout", {})):
        status, _, payload = client.request(method, path, json_body=body)
        assert status == 401, payload
    status, _, payload = client.request("GET", "/api/v1/status")
    assert status == 401

    # Page contract: 401 freezes actions and prompts reauthentication.
    status, _, script = get(client, "/static/app.js")
    source = script.decode("utf-8")
    assert "freezeForReauthentication" in function_source(source, "pollNow")
    _, _, page = get(client, "/")
    assert "expiró".encode() in page or "expiró" in page.decode("utf-8")


def test_lost_cancel_ack_no_automatic_next(tmp_path):
    config = make_config(tmp_path)
    runtime, secret = browser_runtime(config)
    client = Client(make_upload_app(runtime))
    media = (FIXTURE_ROOT / "P2-mp3-libmp3lame.mp3").read_bytes()
    client.login(secret)
    status, _, active = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "lost.mp3", "file_bytes": len(media)})
    assert status == 201
    # The cancel request is issued and its acknowledgement is lost (the
    # owning client discards the response); the server still cancels the
    # transfer and the queue may only proceed after reconciliation.
    status, _, payload = client.request("POST", f"/api/v1/uploads/{active['upload_id']}/cancel",
                                        json_body={})
    assert status == 200
    status, _, record = client.request("GET", f"/api/v1/uploads/{active['upload_id']}")
    assert status == 200 and record["outcome"] == "cancelled"
    status, _, nxt = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "next.mp3", "file_bytes": 10})
    assert status == 201 and nxt["upload_id"] != active["upload_id"]

    # Page contract: a lost cancel acknowledgement stays uncertain and never
    # starts the next item on its own.
    status, _, script = get(client, "/static/app.js")
    source = script.decode("utf-8")
    lost_body = function_source(source, "handleLostBody")
    assert "UNCERTAIN" in lost_body
    assert "pump(" not in lost_body
    assert "manualRetry(" not in lost_body
    reconcile_body = function_source(source, "reconcile")
    assert "api/v1/uploads/" in reconcile_body, "lost acks reconcile through the owning lookup"


def test_regression_upload_suites_still_contractual(tmp_path):
    """Regression anchor: the browser contract keeps the same-origin defenses
    (multipart/encoding rejection, CSRF, secure cookie) and the served page
    keeps no media download route."""
    config = make_config(tmp_path)
    runtime, secret = browser_runtime(config)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    status, _, payload = client.request(
        "POST", "/api/v1/uploads",
        headers=[(b"content-type", b"multipart/form-data; boundary=x")], body=b"")
    assert status == 415 and payload["error"] == "invalid_media"
    status, _, payload = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "x.mp3"},
        headers=[(b"content-encoding", b"gzip")])
    assert status == 415
    status, _, payload = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "x.mp3"},
        headers=[(b"x-csrf-token", b"wrong")])
    assert status == 403
    for path in ("/static/index.html", "/static/app.css.js", "/static/upload-staging.mp3"):
        status, _, _ = get(client, path)
        assert status == 404, f"{path} must not be served"
