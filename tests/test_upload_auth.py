import base64
import hashlib

import json

import pytest

from audioscribe.service import InstanceLock
from audioscribe.upload import auth
from audioscribe.upload.auth import generate_secret, generate_secret_offline, verify_secret


def test_generation_only_secret_display():
    secret, verifier = generate_secret()

    assert len(secret) == 43
    decoded = base64.urlsafe_b64decode(secret + "=")
    assert len(decoded) == 32
    assert verifier == hashlib.sha256(decoded).hexdigest()
    assert secret not in verifier


def test_raw_bytes_verifier_login_roundtrip():
    secret, verifier = generate_secret()

    assert verify_secret(secret, verifier)
    assert not verify_secret(base64.urlsafe_b64encode(b"x" * 32).decode().rstrip("="), verifier)


def test_secret_decoder_rejects_noncanonical_encodings():
    _, verifier = generate_secret()

    assert not verify_secret("A" * 43, verifier)
    assert not verify_secret("A" * 42 + "=", verifier)


def test_constant_time_verifier_contract_rejects_malformed_verifier():
    secret, _ = generate_secret()

    assert verify_secret(secret, None) is False


def test_offline_mutation_takes_instance_lock(tmp_path):
    lock = InstanceLock(tmp_path / "service.lock")
    try:
        with pytest.raises(RuntimeError, match="ya se está ejecutando"):
            generate_secret_offline(tmp_path)
        assert not (tmp_path / "upload-auth" / "verifier.json").exists()
    finally:
        lock.close()


def test_offline_secret_is_returned_after_verifier_only_persistence(tmp_path):
    secret = generate_secret_offline(tmp_path)
    verifier_file = tmp_path / "upload-auth" / "verifier.json"
    persisted = json.loads(verifier_file.read_text(encoding="utf-8"))

    assert set(persisted) == {"sha256"}
    assert verify_secret(secret, persisted["sha256"])
    assert secret not in verifier_file.read_text(encoding="utf-8")


def test_windows_acl_failure_aborts_before_credential_persistence(tmp_path, monkeypatch):
    def reject_acl(_directory):
        raise PermissionError("private ACL setup failed")

    monkeypatch.setattr(auth, "_is_windows", lambda: True, raising=False)
    monkeypatch.setattr(auth, "_create_private_windows_directory", reject_acl, raising=False)

    with pytest.raises(PermissionError, match="private ACL"):
        auth.generate_secret_offline(tmp_path)

    assert not (tmp_path / "upload-auth" / "verifier.json").exists()


def test_existing_verifier_is_never_overwritten(tmp_path):
    original_secret = generate_secret_offline(tmp_path)
    verifier_file = tmp_path / "upload-auth" / "verifier.json"
    original_verifier = verifier_file.read_bytes()

    with pytest.raises(FileExistsError):
        generate_secret_offline(tmp_path)

    assert verifier_file.read_bytes() == original_verifier
    assert verify_secret(original_secret, json.loads(original_verifier)["sha256"])


def test_posix_verifier_directory_and_file_are_private(tmp_path):
    import os
    import stat

    if os.name == "nt":
        pytest.skip("Native Windows ACL verification is a target qualification obligation.")
    generate_secret_offline(tmp_path)
    directory = tmp_path / "upload-auth"
    verifier_file = directory / "verifier.json"

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(verifier_file.stat().st_mode) == 0o600
