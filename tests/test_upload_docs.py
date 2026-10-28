"""PLAN-05 step 4: operator deployment documentation matches the verified
CLI and the Serve security boundary.

The operator guide must tell the truth about what the application does and
does not do: the app never configures Serve, the backend is loopback-only,
authentication does not encrypt, raw HTTP on the LAN exposes credentials and
files, there is no Funnel and no direct-LAN fallback, and the shared secret
is generated locally and displayed exactly once.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUIDE = ROOT / "docs" / "UPLOAD-SERVE.md"
README = ROOT / "README.md"

CLI_COMMANDS = (
    "upload enable",
    "upload disable",
    "upload status",
    "upload regenerate-secret",
    "stop --force",
)
SERVE_COMMANDS = (
    "tailscale serve --bg --https=443 http://127.0.0.1:8765",
    "tailscale serve status",
    "tailscale funnel status",
)


def test_deployment_instructions_match_cli():
    assert GUIDE.is_file(), "docs/UPLOAD-SERVE.md is missing"
    guide = GUIDE.read_text(encoding="utf-8")

    for command in CLI_COMMANDS:
        assert command in guide, f"the guide must use the verified CLI spelling: {command}"
    for command in SERVE_COMMANDS:
        assert command in guide, f"the guide must give the exact Serve command: {command}"

    # Prerequisites and disclosures.
    for topic in ("MagicDNS", "HTTPS"):
        assert topic in guide, f"prerequisite missing: {topic}"
    assert "certificate" in guide.lower()
    assert "transparency" in guide.lower(), \
        "the certificate-transparency disclosure must be stated plainly"

    # Verification steps: the operator must curl the certified hostname.
    assert "curl" in guide and ".ts.net" in guide, \
        "verification must curl the certified HTTPS hostname"

    # Security limitations, stated plainly.
    assert "does not encrypt" in guide.lower() or "is not encryption" in guide.lower(), \
        "the guide must say the app's authentication does not encrypt traffic"
    assert "127.0.0.1:8765" in guide, "the loopback backend binding must be documented"
    assert "Funnel" in guide, "the no-Funnel boundary must be documented"
    assert "LAN" in guide, "the raw-HTTP-on-LAN exposure must be documented"

    # The application must never claim to configure Serve itself.
    assert "never configures" in guide.lower() or "the app does not" in guide.lower()


def test_readme_points_to_the_deployment_guide():
    readme = README.read_text(encoding="utf-8")
    assert "docs/UPLOAD-SERVE.md" in readme, \
        "the README must point operators to the deployment guide"
