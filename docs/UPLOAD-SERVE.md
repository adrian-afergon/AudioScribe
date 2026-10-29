# Serving AudioScribe uploads over Tailscale (operator guide)

This guide is for the person who runs the AudioScribe server and wants to upload media
from other devices on their private tailnet through the browser page. The upload service
listens only on the server's loopback interface; Tailscale Serve provides the HTTPS
entry point from the rest of the tailnet. **The application never configures Serve** —
you do, manually, with the commands below.

## Before you start

| Prerequisite | Where to check |
|---|---|
| Tailscale installed and logged in on the server and on every device you will upload from | `tailscale status` |
| MagicDNS enabled for the tailnet | Tailscale admin console → DNS |
| HTTPS certificates enabled for the tailnet | Tailscale admin console → DNS → HTTPS Certificates |
| Certified hostname known (for example `audioscribe.your-tailnet.ts.net`) | Tailscale admin console → DNS |

One disclosure to understand before issuing the certificate: Tailscale logs
`.ts.net` certificates publicly in **certificate-transparency logs**. That reveals the
hostname's existence — not its traffic or contents. If that disclosure is unacceptable
for your tailnet name, do not deploy this feature.

The backend always binds `127.0.0.1:8765` only. Nothing else may reach it directly:
no LAN binding, no port forwarding, no router exposure.

## Quick path

1. Enable uploads and capture the secret (displayed exactly once):

   ```text
   PYTHON -m audioscribe --config CONFIG upload enable
   ```

   Set `upload_origin` in `config.toml` to the certified canonical origin before
   enabling, for example `upload_origin = "https://audioscribe.your-tailnet.ts.net"`.
   If uploads were enabled with a different origin, run `upload disable`, fix the
   origin, and `upload enable` again.

2. Configure Serve yourself (the app does not do this):

   ```text
   tailscale serve --bg --https=443 http://127.0.0.1:8765
   tailscale serve status
   tailscale funnel status
   ```

   `serve status` must show the mapping from `https://YOUR-HOST.ts.net` (port 443) to
   `http://127.0.0.1:8765`. `funnel status` must show **no Funnel** — this deployment
   never exposes anything to the public internet.

3. Verify from another tailnet device:

   ```text
   curl https://YOUR-HOST.ts.net/api/v1/auth/challenge
   ```

   The certificate must validate and the challenge endpoint must answer with a small
   JSON object (same-origin GETs carry no `Origin` header; the certified Host is what
   the backend checks here). Then open the same hostname in a browser and log in with
   the secret from step 1.

4. To stop serving: `tailscale serve --https=443 off`, and to stop accepting uploads:
   `PYTHON -m audioscribe --config CONFIG upload disable` (add `--force` only to cancel
   active uploads; plain `stop --force` also cancels unpublished uploads).

## Security limits — read before deploying

- **Authentication is not encryption.** The shared-secret login controls who may use
  the upload page; it does not protect traffic on its own. Encryption comes from
  Serve's HTTPS. Raw HTTP access to the backend — on the LAN or anywhere else —
  exposes credentials and media files in the clear. There is no HTTP/LAN fallback and
  no direct-LAN deployment mode; this is deferred and unsupported.
- **No Funnel.** `tailscale funnel` would expose the page to the public internet.
  This feature never supports it; keep `funnel status` empty.
- **Trusted-host boundary.** The backend accepts only original loopback peers and
  expects Serve's forwarding. Other processes running on the server itself can spoof
  loopback headers — protect the server account accordingly.
- **Forwarding headers (documented policy).** Tailscale Serve adds one
  `X-Forwarded-For` hop when proxying to the loopback backend. The backend tolerates
  exactly that single hop: a lone `X-Forwarded-For` (or `X-Real-IP`) value is accepted
  and never used as identity or authorization — access control is the shared secret,
  the session cookie and the certified hostname. Requests presenting a multi-hop
  chain (comma-separated addresses), duplicated forwarding header lines, or an
  unexpected proxy topology are rejected with `403`. No proxy configuration is
  required from the operator; if Serve's behavior changes so this policy no longer
  matches, enable qualification fails closed instead of relaxing the boundary.
- **Secret handling.** `upload enable` prints the secret once, to your terminal; store
  it in a password manager and never pass it on a command line, in a URL, or in a
  script. If you did not capture it cleanly, run `upload regenerate-secret` (this
  invalidates every session and cancels unpublished uploads) rather than guessing.

## Secret workflow

| Action | Command | Effect |
|---|---|---|
| First enable | `upload enable` | Generates the secret in memory, displays it once, persists only its verifier |
| Reveal again | — | Impossible; regenerate instead |
| Rotate | `upload regenerate-secret` | Invalidates every session, cancels all unpublished uploads, displays the new secret once |
| Uncertain outcome | `upload status` | Check state; never re-run generation blindly |

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Browser shows certificate warnings | MagicDNS or HTTPS certificates are not enabled for the tailnet |
| `403` on every request | `upload_origin` in `config.toml` does not exactly match the certified `https://….ts.net` origin |
| Uploads enabled but the page does not answer | `tailscale serve status` has no mapping, or the backend service is not running |
| Status reports the listener off with a cause | The enable preflight failed (for example the destination mount does not support atomic no-overwrite links); fix the cause and enable again — the saved choice stays preserved |

## Checklist

- [ ] `tailscale serve status` shows 443 → `http://127.0.0.1:8765`
- [ ] `tailscale funnel status` shows nothing
- [ ] `curl https://YOUR-HOST.ts.net/api/v1/auth/challenge` answers with JSON
- [ ] Login works from another tailnet device over HTTPS
- [ ] The secret is stored in a password manager and absent from shell history
