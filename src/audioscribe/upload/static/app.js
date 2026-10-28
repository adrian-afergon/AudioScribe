"use strict";

/* AudioScribe upload page. Transient client-side queue: nothing about the
 * queue or the continuity proof survives a refresh; browser storage is never
 * used and no upload is ever retried automatically. */

const POLL_INTERVAL_MS = 1000;

const UPLOAD_PHASES = {
  QUEUED: "queued",
  STARTING: "starting",
  STREAMING: "streaming",
  PUBLISHED: "published",
  REJECTED: "rejected",
  CANCELLED: "cancelled",
  ERROR: "error",
  UNCERTAIN: "uncertain",
};

const TERMINAL_PHASES = new Set([
  UPLOAD_PHASES.PUBLISHED,
  UPLOAD_PHASES.REJECTED,
  UPLOAD_PHASES.CANCELLED,
  UPLOAD_PHASES.ERROR,
]);

/* Downstream transcription states come only from the one-second status poll;
 * they are displayed separately from the upload lifecycle. */
const DOWNSTREAM_LABELS = {
  awaiting_scanner: "Esperando al escáner",
  queued: "En cola",
  processing: "Procesando",
  completed: "Completado",
  error: "Error",
  reused: "Reutilizado",
};

const PHASE_LABELS = {
  queued: "En cola local",
  starting: "Iniciando",
  streaming: "Enviando",
  published: "Subida publicada",
  rejected: "Rechazada",
  cancelled: "Cancelada",
  error: "Error",
  uncertain: "Sin confirmación del servidor",
};

const session = {
  csrf: null,
  continuityProof: null,
};

const view = {
  concurrency: 0,
  activeStarts: 0,
  items: [],
  history: [],
  stale: false,
  frozen: false,
  pollInFlight: false,
  localSequence: 0,
};

function byId(id) {
  return document.getElementById(id);
}

function labelFor(element, text) {
  element.textContent = text;
}

async function apiRequest(path, options) {
  const headers = new Headers(options.headers || {});
  if (options.json !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  if (session.csrf && options.csrf !== false) {
    headers.set("X-CSRF-Token", session.csrf);
  }
  const response = await fetch(path, {
    method: options.method || "GET",
    headers,
    body: options.json !== undefined ? JSON.stringify(options.json) : options.body,
    credentials: "same-origin",
  });
  let payload = null;
  const text = await response.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (parseError) {
      payload = null;
    }
  }
  return { status: response.status, payload };
}

function showLogin(reauth) {
  byId("app-panel").hidden = true;
  byId("login-panel").hidden = false;
  byId("logout").hidden = true;
  byId("reauth-note").hidden = !reauth;
}

function showApp() {
  byId("login-panel").hidden = true;
  byId("app-panel").hidden = false;
  byId("logout").hidden = false;
}

async function login(secret) {
  const challenge = await apiRequest("/api/v1/auth/challenge", { csrf: false });
  if (challenge.status !== 200 || !challenge.payload) {
    throw new Error("no_challenge");
  }
  const attempt = await apiRequest("/api/v1/auth/login", {
    method: "POST",
    csrf: false,
    json: {
      secret,
      csrf: challenge.payload.nonce,
      continuity_proof: session.continuityProof,
    },
  });
  if (attempt.status !== 200 || !attempt.payload) {
    throw new Error("login_rejected");
  }
  /* Both values live only in page memory; a refresh discards them. */
  session.csrf = attempt.payload.csrf;
  session.continuityProof = attempt.payload.continuity_proof;
  view.frozen = false;
  showApp();
  await pollNow();
}

async function logout() {
  try {
    await apiRequest("/api/v1/auth/logout", { method: "POST", json: {} });
  } catch (transportError) {
    /* The session may still be revoked server-side; memory is cleared either way. */
  }
  session.csrf = null;
  session.continuityProof = null;
  view.frozen = true;
  view.items = [];
  view.activeStarts = 0;
  view.history = [];
  renderQueue();
  showLogin(false);
}

function onFilesChosen(fileList) {
  if (view.frozen) {
    return;
  }
  for (const file of fileList) {
    view.localSequence += 1;
    view.items.push({
      localId: view.localSequence,
      file,
      name: file.name,
      size: file.size,
      phase: UPLOAD_PHASES.QUEUED,
      sent: 0,
      uploadId: null,
      transferToken: null,
      downstream: null,
      error: null,
      cancelRequested: false,
      xhr: null,
    });
  }
  renderQueue();
  pump();
}

/* At most `concurrency` transfers start simultaneously; the waiting queue is
 * transient, local and not capped by the server's limit. The server rejects
 * excess admission immediately and the item simply stays queued. */
function pump() {
  if (view.frozen) {
    return;
  }
  while (view.activeStarts < view.concurrency) {
    const next = view.items.find((item) => item.phase === UPLOAD_PHASES.QUEUED);
    if (!next) {
      return;
    }
    startNext(next);
  }
}

async function startNext(item) {
  view.activeStarts += 1;
  item.phase = UPLOAD_PHASES.STARTING;
  renderQueue();
  let registration;
  try {
    registration = await apiRequest("/api/v1/uploads", {
      method: "POST",
      json: { filename: item.name, file_bytes: item.size },
    });
  } catch (transportError) {
    view.activeStarts -= 1;
    item.phase = UPLOAD_PHASES.ERROR;
    item.error = "registration_unreachable";
    renderQueue();
    return;
  }
  if (registration.status === 201 && registration.payload) {
    item.uploadId = registration.payload.upload_id;
    item.transferToken = registration.payload.transfer_token;
    streamFile(item);
    return;
  }
  view.activeStarts -= 1;
  if (registration.status === 409) {
    /* Backpressure: the server has no waiting queue. The item returns to the
     * local queue and is retried only when a slot release is confirmed. */
    item.phase = UPLOAD_PHASES.QUEUED;
    item.error = null;
  } else {
    item.phase = UPLOAD_PHASES.REJECTED;
    item.error = registration.payload ? registration.payload.error : "rejected";
  }
  renderQueue();
}

function streamFile(item) {
  item.phase = UPLOAD_PHASES.STREAMING;
  renderQueue();
  const xhr = new XMLHttpRequest();
  item.xhr = xhr;
  xhr.open("POST", `/api/v1/uploads/${encodeURIComponent(item.uploadId)}/body`, true);
  xhr.setRequestHeader("Content-Type", "application/octet-stream");
  xhr.setRequestHeader("x-transfer-token", item.transferToken);
  if (session.csrf) {
    xhr.setRequestHeader("X-CSRF-Token", session.csrf);
  }
  xhr.upload.onprogress = (event) => {
    item.sent = event.loaded;
    renderQueue();
  };
  xhr.onload = () => {
    item.xhr = null;
    let payload = null;
    try {
      payload = JSON.parse(xhr.responseText);
    } catch (parseError) {
      payload = null;
    }
    finishBody(item, xhr.status, payload);
  };
  xhr.onerror = () => {
    item.xhr = null;
    if (item.cancelRequested) {
      confirmCancel(item);
      return;
    }
    handleLostBody(item);
  };
  xhr.onabort = () => {
    item.xhr = null;
    if (item.cancelRequested) {
      confirmCancel(item);
    }
  };
  xhr.send(item.file);
}

/* A lost body acknowledgement proves nothing: the slot stays occupied until
 * GET /uploads/{id} reconciles the transfer. No next item starts from here. */
function handleLostBody(item) {
  item.phase = UPLOAD_PHASES.UNCERTAIN;
  renderQueue();
}

function finishBody(item, status, payload) {
  view.activeStarts -= 1;
  if (status === 200 && payload) {
    item.phase = UPLOAD_PHASES.PUBLISHED;
    item.downstream = payload.downstream || null;
  } else if (status === 409 && payload && payload.error === "cancelled") {
    item.phase = UPLOAD_PHASES.CANCELLED;
  } else {
    item.phase = UPLOAD_PHASES.REJECTED;
    item.error = payload ? payload.error : `http_${status}`;
  }
  item.transferToken = null;
  renderQueue();
  pump();
}

function confirmCancel(item) {
  view.activeStarts -= 1;
  item.phase = UPLOAD_PHASES.CANCELLED;
  item.transferToken = null;
  renderQueue();
  pump();
}

async function cancelItem(item) {
  if (item.phase === UPLOAD_PHASES.QUEUED) {
    /* Removing a queued item is purely local: no server reservation exists. */
    view.items = view.items.filter((entry) => entry !== item);
    renderQueue();
    return;
  }
  if (item.cancelRequested || TERMINAL_PHASES.has(item.phase)) {
    return;
  }
  item.cancelRequested = true;
  if (item.xhr) {
    item.xhr.abort();
    return;
  }
  try {
    const outcome = await apiRequest(`/api/v1/uploads/${encodeURIComponent(item.uploadId)}/cancel`, {
      method: "POST",
      json: {},
    });
    if (outcome.status === 200) {
      if (view.activeStarts > 0) {
        view.activeStarts -= 1;
      }
      item.phase = UPLOAD_PHASES.CANCELLED;
    } else if (outcome.status === 404) {
      item.phase = UPLOAD_PHASES.UNCERTAIN;
    } else if (outcome.status === 401) {
      freezeForReauthentication();
      return;
    } else {
      item.phase = UPLOAD_PHASES.UNCERTAIN;
    }
  } catch (transportError) {
    item.phase = UPLOAD_PHASES.UNCERTAIN;
  }
  renderQueue();
  pump();
}

/* Manual-only retry: always a fresh registration with a new upload identity;
 * the old attempt keeps its terminal outcome. */
function manualRetry(item) {
  if (!TERMINAL_PHASES.has(item.phase) || view.frozen) {
    return;
  }
  view.localSequence += 1;
  view.items.push({
    localId: view.localSequence,
    file: item.file,
    name: item.name,
    size: item.size,
    phase: UPLOAD_PHASES.QUEUED,
    sent: 0,
    uploadId: null,
    transferToken: null,
    downstream: null,
    error: null,
    cancelRequested: false,
    xhr: null,
  });
  renderQueue();
  pump();
}

async function reconcile(item) {
  try {
    const outcome = await apiRequest(`/api/v1/uploads/${encodeURIComponent(item.uploadId)}`);
    if (outcome.status === 200 && outcome.payload) {
      const record = outcome.payload;
      if (TERMINAL_OUTCOMES.has(record.outcome)) {
        if (view.activeStarts > 0) {
          view.activeStarts -= 1;
        }
        item.phase = record.outcome === "cancelled" ? UPLOAD_PHASES.CANCELLED
          : record.outcome === "published" ? UPLOAD_PHASES.PUBLISHED
          : UPLOAD_PHASES.REJECTED;
        item.transferToken = null;
        item.downstream = record.downstream || null;
        renderQueue();
        pump();
      }
      return;
    }
    if (outcome.status === 401) {
      freezeForReauthentication();
    }
    /* 404 outcome_unavailable proves nothing: never infer a failure here. */
  } catch (transportError) {
    /* Stays uncertain until a later poll succeeds. */
  }
}

const TERMINAL_OUTCOMES = new Set(["published", "cancelled", "failed",
  "published-with-cleanup-error", "cleanup_failed"]);

function freezeForReauthentication() {
  view.frozen = true;
  showLogin(true);
}

/* Poll once per second without overlap: a skipped tick simply waits for the
 * next interval. Poll failures mark the view stale; they never restart an
 * upload, never force reauthentication and never imply a failed transfer. */
async function pollNow() {
  if (view.pollInFlight || view.frozen) {
    return;
  }
  view.pollInFlight = true;
  let nextDelay = POLL_INTERVAL_MS;
  try {
    const snapshot = await apiRequest("/api/v1/status", { csrf: false });
    if (snapshot.status === 200 && snapshot.payload) {
      view.stale = false;
      if (snapshot.payload.concurrency) {
        view.concurrency = snapshot.payload.concurrency;
      }
      view.history = snapshot.payload.history || [];
      applyDownstream();
      await reconcileUncertain();
    } else if (snapshot.status === 503) {
      view.stale = true;
    } else if (snapshot.status === 401) {
      freezeForReauthentication();
    } else {
      view.stale = true;
    }
  } catch (transportError) {
    view.stale = true;
  } finally {
    view.pollInFlight = false;
    renderHistory();
    renderQueue();
    renderStatusLine();
    if (!view.frozen) {
      window.setTimeout(pollNow, nextDelay);
    }
  }
}

function applyDownstream() {
  const rows = new Map(view.history.map((row) => [row.upload_id, row]));
  for (const item of view.items) {
    if (!item.uploadId) {
      continue;
    }
    const row = rows.get(item.uploadId);
    if (row && row.downstream) {
      item.downstream = row.downstream;
    }
  }
}

async function reconcileUncertain() {
  const pending = view.items.filter((item) => item.phase === UPLOAD_PHASES.UNCERTAIN);
  for (const item of pending) {
    await reconcile(item);
  }
}

function formatBytes(value) {
  if (value === null || value === undefined) {
    return "";
  }
  return `${value} B`;
}

function renderStatusLine() {
  const line = byId("status-line");
  labelFor(line, `Subidas simultáneas admitidas: ${view.concurrency}`);
  byId("stale-badge").hidden = !view.stale;
}

function renderQueue() {
  const list = byId("queue-list");
  list.textContent = "";
  for (const item of view.items) {
    const entry = document.createElement("li");
    entry.className = "queue-item";

    const name = document.createElement("div");
    name.className = "name";
    labelFor(name, item.name);

    const phase = document.createElement("div");
    phase.className = "phase";
    labelFor(phase, PHASE_LABELS[item.phase] || item.phase);

    const uploadLine = document.createElement("div");
    labelFor(uploadLine,
      `Enviados: ${formatBytes(item.sent)} / ${formatBytes(item.size)}`);

    const downstream = document.createElement("div");
    downstream.className = "downstream-label";
    labelFor(downstream, item.downstream
      ? `Procesamiento: ${DOWNSTREAM_LABELS[item.downstream] || item.downstream}`
      : "Procesamiento: —");

    const track = document.createElement("div");
    track.className = "progress-track";
    const fill = document.createElement("div");
    fill.className = "progress-fill";
    if (item.size > 0) {
      fill.style.width = `${Math.min(100, Math.round((item.sent / item.size) * 100))}%`;
    }
    track.appendChild(fill);

    const actions = document.createElement("div");
    if (!TERMINAL_PHASES.has(item.phase) && item.phase !== UPLOAD_PHASES.UNCERTAIN) {
      const cancel = document.createElement("button");
      cancel.type = "button";
      labelFor(cancel, "Cancelar");
      cancel.addEventListener("click", () => cancelItem(item));
      actions.appendChild(cancel);
    }
    if (TERMINAL_PHASES.has(item.phase) && item.phase !== UPLOAD_PHASES.PUBLISHED) {
      const retry = document.createElement("button");
      retry.type = "button";
      labelFor(retry, "Reintentar");
      retry.addEventListener("click", () => manualRetry(item));
      actions.appendChild(retry);
    }

    entry.appendChild(name);
    entry.appendChild(phase);
    entry.appendChild(uploadLine);
    entry.appendChild(track);
    entry.appendChild(downstream);
    if (item.error) {
      const error = document.createElement("div");
      error.className = "error";
      labelFor(error, `Detalle: ${item.error}`);
      entry.appendChild(error);
    }
    entry.appendChild(actions);
    list.appendChild(entry);
  }
}

function renderHistory() {
  const body = byId("history-body");
  body.textContent = "";
  for (const row of view.history) {
    const tr = document.createElement("tr");

    const name = document.createElement("td");
    labelFor(name, row.name || "");
    const outcome = document.createElement("td");
    labelFor(outcome, row.outcome || row.state || "");
    const downstream = document.createElement("td");
    labelFor(downstream, row.downstream ? DOWNSTREAM_LABELS[row.downstream] || row.downstream : "—");
    const bytes = document.createElement("td");
    labelFor(bytes, formatBytes(row.bytes_received));
    const detail = document.createElement("td");
    labelFor(detail, row.error_code || "");

    tr.appendChild(name);
    tr.appendChild(outcome);
    tr.appendChild(downstream);
    tr.appendChild(bytes);
    tr.appendChild(detail);
    body.appendChild(tr);
  }
}

function wireEvents() {
  byId("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const errorLine = byId("login-error");
    errorLine.hidden = true;
    try {
      await login(byId("secret").value);
      byId("secret").value = "";
    } catch (loginError) {
      labelFor(errorLine, "El secreto no fue aceptado o el servidor no respondió.");
      errorLine.hidden = false;
    }
  });
  byId("logout").addEventListener("click", () => logout());
  byId("file-input").addEventListener("change", (event) => {
    onFilesChosen(Array.from(event.target.files || []));
    event.target.value = "";
  });
}

wireEvents();
showLogin(false);
