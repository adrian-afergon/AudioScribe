"""Behavioral execution of the served browser script (review required-action 1).

The static contract suite proved insufficient: the undefined `API` identifier
and the missing X-CSRF-Token header on the body XHR escaped string inspection.
This suite executes the actual bytes served at /static/app.js inside a Node
VM with a minimal DOM/XHR/fetch stub, drives the exact flow the page performs
(login, registration, raw body XHR) and asserts the real requests the script
produces. Skipped only when no node runtime is available.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from audioscribe.upload.auth import generate_secret_offline
from audioscribe.upload.http import make_upload_app
from test_upload_http import Client, make_config, make_runtime

HARNESS = r"""
"use strict";
const fs = require("node:fs");
const vm = require("node:vm");

const script = fs.readFileSync(process.argv[2], "utf8");

// -- minimal browser stubs ---------------------------------------------------
const recorded = { fetch: [], xhr: [] };
let fetchResponses = [];
let fetchQueue = [];

function elementStub() {
  const listeners = {};
  return {
    hidden: true,
    textContent: "",
    value: "",
    className: "",
    style: {},
    files: [],
    addEventListener(kind, handler) { listeners[kind] = handler; },
    appendChild() {},
    setAttribute() {},
  };
}

globalThis.document = {
  getElementById() { return elementStub(); },
  createElement() { return elementStub(); },
};
globalThis.window = { setTimeout() {} };

globalThis.fetch = async function fetch(url, options) {
  recorded.fetch.push({ url, options });
  const response = fetchQueue.shift();
  if (!response) {
    throw new Error("unexpected fetch: " + url);
  }
  return { status: response.status, text: async () => response.body };
};

class XMLHttpRequest {
  constructor() {
    this.headers = {};
    this.upload = {};
  }
  open(method, url, async) {
    this.method = method;
    this.url = url;
    this.async = async;
  }
  setRequestHeader(name, value) {
    this.headers[name] = value;
  }
  send(body) {
    this.body = body;
    recorded.xhr.push(this);
  }
}
globalThis.XMLHttpRequest = XMLHttpRequest;

// -- execute the real served script -------------------------------------------
const context = { console, Headers, XMLHttpRequest, fetch, document, window };
vm.createContext(context);
vm.runInContext(script, context, { filename: "app.js" });

(async () => {
  const flow = JSON.parse(process.argv[3]);
  // Login flow exactly as the page performs it (challenge, login, first poll).
  fetchQueue = [
    { status: 200, body: JSON.stringify({ nonce: flow.nonce, expires_in: 60 }) },
    { status: 200, body: JSON.stringify({ csrf: flow.csrf, continuity_proof: flow.proof }) },
    { status: 200, body: JSON.stringify({ history: [], concurrency: 1 }) },
  ];
  await context.login(flow.secret);
  if (recorded.fetch.length !== 3
      || recorded.fetch[0].url !== "/api/v1/auth/challenge"
      || recorded.fetch[1].url !== "/api/v1/auth/login"
      || recorded.fetch[2].url !== "/api/v1/status") {
    throw new Error("unexpected login fetch sequence: " + JSON.stringify(recorded.fetch));
  }

  // The raw body XHR exactly as the page performs it.
  const item = {
    localId: 1, file: { name: "clip.mp3" }, name: "clip.mp3", size: 3,
    phase: "starting", sent: 0, uploadId: flow.uploadId,
    transferToken: flow.token, downstream: null, error: null,
    cancelRequested: false, xhr: null,
  };
  vm.runInContext("view.concurrency = 1; view.activeStarts = 1;", context);
  context.__item = item;
  vm.runInContext("streamFile(__item)", context);

  const xhr = recorded.xhr[0];
  const report = {
    method: xhr.method,
    url: xhr.url,
    headers: xhr.headers,
    bodyKind: xhr.body === item.file ? "file-reference" : "other",
    fetchUrls: recorded.fetch.map((entry) => entry.url),
    loginHeaders: recorded.fetch[1].options.headers instanceof Headers
      ? Array.from(recorded.fetch[1].options.headers.entries())
      : Object.fromEntries(new Headers(recorded.fetch[1].options.headers || {}).entries()),
  };
  process.stdout.write(JSON.stringify(report));
})().catch((error) => {
  process.stderr.write(String(error && error.stack ? error.stack : error));
  process.exit(1);
});
"""


def _served_script(tmp_path: Path, client: Client) -> Path:
    status, _, body = _raw_get(client, "/static/app.js")
    assert status == 200
    path = tmp_path / "served-app.js"
    path.write_bytes(body)
    return path


def _runtime_with_secret(config):
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    return runtime, secret


def _raw_get(client, path):
    import asyncio

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
        loop.run_until_complete(client.app(scope, receive, send))
        status = next(m["status"] for m in sent if m["type"] == "http.response.start")
        body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
        return status, None, body
    finally:
        loop.close()


def _run_node(script_path: Path, flow: dict) -> dict:
    process = subprocess.run(
        [shutil.which("node") or "node", "-e", HARNESS, "harness", str(script_path),
         json.dumps(flow)],
        capture_output=True, text=True, timeout=30, check=False)
    if process.returncode != 0:
        raise AssertionError(f"browser script harness failed:\n{process.stderr}")
    return json.loads(process.stdout)


@pytest.mark.skipif(shutil.which("node") is None, reason="no node runtime available")
def test_served_script_streams_body_with_relative_url_and_csrf(tmp_path):
    (tmp_path / "app").mkdir()
    config = make_config(tmp_path / "app")
    runtime, secret = _runtime_with_secret(config)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    status, _, registration = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "clip.mp3", "file_bytes": 16})
    assert status == 201

    harness_dir = tmp_path / "harness"
    harness_dir.mkdir()
    script = _served_script(harness_dir, client)
    report = _run_node(script, {
        "secret": secret,
        "nonce": "unused-by-stub",
        "csrf": client.csrf,
        "proof": "unused-by-stub",
        "uploadId": registration["upload_id"],
        "token": registration["transfer_token"],
    })

    # The XHR the page actually emits: same-origin relative URL, no undefined
    # identifier, transfer token AND session CSRF headers on the mutation.
    assert report["method"] == "POST"
    assert report["url"] == f"/api/v1/uploads/{registration['upload_id']}/body"
    assert report["headers"].get("x-transfer-token") == registration["transfer_token"]
    assert report["headers"].get("X-CSRF-Token") == client.csrf
    assert report["headers"].get("Content-Type") == "application/octet-stream"
    assert report["bodyKind"] == "file-reference"
    assert report["fetchUrls"] == ["/api/v1/auth/challenge", "/api/v1/auth/login",
                                   "/api/v1/status"]
    login_headers = {str(name).lower(): value for name, value in report["loginHeaders"]}
    assert login_headers.get("content-type") == "application/json"


@pytest.mark.skipif(shutil.which("node") is None, reason="no node runtime available")
def test_served_script_never_references_undefined_identifiers(tmp_path):
    config = make_config(tmp_path)
    runtime, _secret = _runtime_with_secret(config)
    client = Client(make_upload_app(runtime))
    status, _, body = _raw_get(client, "/static/app.js")
    assert status == 200
    script_path = tmp_path / "served-app.js"
    script_path.write_bytes(body)
    # Syntax-level execution check: any free identifier at module scope that is
    # not defined fails this parse-and-execute round trip inside the VM.
    probe = (
        "const fs=require('node:fs'),vm=require('node:vm');"
        "const src=fs.readFileSync(process.argv[1],'utf8');"
        "const ctx={console,Headers,XMLHttpRequest:function(){this.headers={};this.upload={};"
        "this.open=()=>{};this.setRequestHeader=()=>{};this.send=()=>{}},"
        "fetch:async()=>({status:403,text:async()=>''}),"
        "document:{getElementById:()=>({hidden:false,textContent:'',value:'',style:{},"
        "addEventListener(){},appendChild(){}}),createElement:()=>({hidden:false,"
        "textContent:'',style:{},addEventListener(){},appendChild(){}})},"
        "window:{setTimeout(){}}};"
        "vm.createContext(ctx);vm.runInContext(src,ctx,{filename:'app.js'});"
        "process.stdout.write('ok');"
    )
    process = subprocess.run(
        [shutil.which("node") or "node", "-e", probe, str(script_path)],
        capture_output=True, text=True, timeout=30, check=False)
    assert process.returncode == 0, (
        "the served script must execute without reference errors:\n"
        f"{process.stderr}\n{sys.executable}")
    assert process.stdout == "ok"
