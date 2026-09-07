"""Unit and integration tests for container packaging and verification."""

import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from typer.testing import CliRunner

from airgap_audit.cli import app
from airgap_audit.companion import updater
from airgap_audit.core.container import (
    DeviceMismatchError,
    MagicMismatchError,
    PayloadChecksumError,
    RollbackVersionError,
    SignatureError,
    TruncatedContainerError,
    UnsupportedHeaderVersionError,
    inspect_container,
    pack_container,
    unpack_and_verify,
)
from airgap_audit.core.crypto import (
    generate_key_pair,
    save_private_key,
    save_public_key,
)

runner = CliRunner()


KeyFixture = tuple[
    ed25519.Ed25519PrivateKey,
    ed25519.Ed25519PublicKey,
    Path,
    Path,
]


@pytest.fixture
def keys(tmp_path: Path) -> KeyFixture:
    priv, pub = generate_key_pair()
    priv_file = tmp_path / "private_key.pem"
    pub_file = tmp_path / "public_key.pem"
    save_private_key(priv, priv_file)
    save_public_key(pub, pub_file)
    return priv, pub, priv_file, pub_file


def test_pack_and_unpack_success(keys: KeyFixture, tmp_path: Path) -> None:
    priv, pub, _, _ = keys
    payload_file = tmp_path / "dummy_app"
    payload_content = b"\x7fELF-dummy-arm64-binary-data-12345"
    payload_file.write_bytes(payload_content)

    container_file = tmp_path / "lvgl_gui.update"
    pack_container(
        payload_path=payload_file,
        version=1,
        device_id="lvgl_gui",
        private_key=priv,
        out_path=container_file,
    )

    unpacked_payload, header = unpack_and_verify(
        container_path=container_file,
        public_key=pub,
        expected_device_id="lvgl_gui",
        min_version=1,
    )

    assert unpacked_payload == payload_content
    assert header.monotonic_version == 1
    assert header.device_id == "lvgl_gui"
    assert header.payload_length == len(payload_content)


def test_invalid_magic_rejected(keys: KeyFixture, tmp_path: Path) -> None:
    priv, pub, _, _ = keys
    payload_file = tmp_path / "dummy_app"
    payload_file.write_bytes(b"data")

    container_file = tmp_path / "test.update"
    raw = bytearray(pack_container(payload_file, 1, "lvgl_gui", priv))
    raw[0:4] = b"BAD!"
    container_file.write_bytes(raw)

    with pytest.raises(MagicMismatchError):
        unpack_and_verify(container_file, pub)


def test_unsupported_version_rejected(keys: KeyFixture, tmp_path: Path) -> None:
    priv, pub, _, _ = keys
    payload_file = tmp_path / "dummy_app"
    payload_file.write_bytes(b"data")

    container_file = tmp_path / "test.update"
    raw = bytearray(pack_container(payload_file, 1, "lvgl_gui", priv))
    # Header version is at offset 4 (uint32)
    raw[4:8] = struct.pack(">I", 999)
    container_file.write_bytes(raw)

    with pytest.raises(UnsupportedHeaderVersionError):
        unpack_and_verify(container_file, pub)


def test_tampered_signature_rejected(keys: KeyFixture, tmp_path: Path) -> None:
    priv, pub, _, _ = keys
    payload_file = tmp_path / "dummy_app"
    payload_file.write_bytes(b"data")

    container_file = tmp_path / "test.update"
    raw = bytearray(pack_container(payload_file, 1, "lvgl_gui", priv))
    # Signature is at offset 72..136
    raw[72] ^= 0xFF
    container_file.write_bytes(raw)

    with pytest.raises(SignatureError):
        unpack_and_verify(container_file, pub)


def test_tampered_payload_rejected(keys: KeyFixture, tmp_path: Path) -> None:
    priv, pub, _, _ = keys
    payload_file = tmp_path / "dummy_app"
    payload_file.write_bytes(b"authentic binary content")

    container_file = tmp_path / "test.update"
    raw = bytearray(pack_container(payload_file, 1, "lvgl_gui", priv))
    # Tamper with the payload part after 136 bytes
    raw[140] ^= 0xAA
    container_file.write_bytes(raw)

    with pytest.raises(PayloadChecksumError):
        unpack_and_verify(container_file, pub)


def test_device_id_mismatch_rejected(keys: KeyFixture, tmp_path: Path) -> None:
    priv, pub, _, _ = keys
    payload_file = tmp_path / "dummy_app"
    payload_file.write_bytes(b"content")

    container_file = tmp_path / "test.update"
    pack_container(payload_file, 1, "other_device", priv, out_path=container_file)

    with pytest.raises(DeviceMismatchError):
        unpack_and_verify(container_file, pub, expected_device_id="lvgl_gui")


def test_anti_rollback_rejected(keys: KeyFixture, tmp_path: Path) -> None:
    priv, pub, _, _ = keys
    payload_file = tmp_path / "dummy_app"
    payload_file.write_bytes(b"content")

    container_file = tmp_path / "test.update"
    pack_container(payload_file, version=1, device_id="lvgl_gui", private_key=priv, out_path=container_file)

    with pytest.raises(RollbackVersionError):
        unpack_and_verify(container_file, pub, min_version=2)


def test_truncated_container_rejected(tmp_path: Path) -> None:
    _, pub = generate_key_pair()
    short_file = tmp_path / "short.update"
    short_file.write_bytes(b"AGUP\x00\x00")

    with pytest.raises(TruncatedContainerError):
        unpack_and_verify(short_file, pub)


def test_inspect_container(keys: KeyFixture, tmp_path: Path) -> None:
    priv, _, _, _ = keys
    payload_file = tmp_path / "app"
    payload_file.write_bytes(b"12345678")

    pkg = tmp_path / "pkg.update"
    pack_container(payload_file, version=5, device_id="kiosk_display", private_key=priv, out_path=pkg)

    header = inspect_container(pkg)
    assert header.magic == b"AGUP"
    assert header.header_version == 1
    assert header.monotonic_version == 5
    assert header.device_id == "kiosk_display"
    assert header.payload_length == 8
    assert len(header.payload_sha256_hex) == 64


def test_cli_lifecycle(tmp_path: Path) -> None:
    # 1. keygen
    keys_dir = tmp_path / "keys"
    res = runner.invoke(app, ["keygen", "--out-dir", str(keys_dir)])
    assert res.exit_code == 0
    assert (keys_dir / "private_key.pem").is_file()
    assert (keys_dir / "public_key.pem").is_file()

    # 2. package create
    bin_path = tmp_path / "dummy_lvgl"
    bin_path.write_bytes(b"\x7fELFdummy")
    out_pkg = tmp_path / "lvgl_gui.update"

    res = runner.invoke(
        app,
        [
            "package",
            "create",
            "--payload",
            str(bin_path),
            "--version",
            "1",
            "--device-id",
            "lvgl_gui",
            "--key",
            str(keys_dir / "private_key.pem"),
            "--out",
            str(out_pkg),
        ],
    )
    assert res.exit_code == 0
    assert out_pkg.is_file()

    # 3. package inspect
    res = runner.invoke(app, ["package", "inspect", "--package", str(out_pkg)])
    assert res.exit_code == 0
    assert "lvgl_gui" in res.stdout
    assert "AGUP" in res.stdout

    # 4. package verify (success)
    res = runner.invoke(
        app,
        [
            "package",
            "verify",
            "--package",
            str(out_pkg),
            "--key",
            str(keys_dir / "public_key.pem"),
            "--device-id",
            "lvgl_gui",
            "--min-version",
            "1",
        ],
    )
    assert res.exit_code == 0
    assert "Verification Passed" in res.stdout

    # 5. package verify (rollback reject)
    res = runner.invoke(
        app,
        [
            "package",
            "verify",
            "--package",
            str(out_pkg),
            "--key",
            str(keys_dir / "public_key.pem"),
            "--min-version",
            "2",
        ],
    )
    assert res.exit_code != 0
    assert "Rollback rejected" in res.stdout


def test_updater_apply_signed_update_flow(keys: KeyFixture, tmp_path: Path) -> None:
    priv, _pub, _priv_file, pub_file = keys

    target = tmp_path / "target_bin"
    state_file = tmp_path / ".target_bin_hash"
    version_file = tmp_path / ".target_bin_version"

    # Initial state: old binary version 1
    target.write_bytes(b"old binary version 1")
    state_file.write_text(updater.get_file_sha256(target))
    version_file.write_text("1\n")

    # Create signed package version 2
    new_payload = tmp_path / "new_payload"
    new_payload.write_bytes(b"new binary version 2 (signed)")
    pkg_v2 = tmp_path / f"{target.name}.update"
    pack_container(new_payload, version=2, device_id=target.name, private_key=priv, out_path=pkg_v2)

    # 1. Apply update -> Success
    res = updater.apply_signed_update(
        container_path=pkg_v2,
        public_key_path=pub_file,
        target=target,
        state_file=state_file,
        version_file=version_file,
    )
    assert res is True
    assert target.read_bytes() == b"new binary version 2 (signed)"
    assert version_file.read_text().strip() == "2"
    assert (tmp_path / "target_bin.bak").read_bytes() == b"old binary version 1"

    # 2. Re-apply same package -> Skipped
    res2 = updater.apply_signed_update(
        container_path=pkg_v2,
        public_key_path=pub_file,
        target=target,
        state_file=state_file,
        version_file=version_file,
    )
    assert res2 is False

    # 3. Apply rollback package (version 1) -> Rejected
    pkg_v1 = tmp_path / "rollback.update"
    pack_container(new_payload, version=1, device_id=target.name, private_key=priv, out_path=pkg_v1)
    res_rollback = updater.apply_signed_update(
        container_path=pkg_v1,
        public_key_path=pub_file,
        target=target,
        state_file=state_file,
        version_file=version_file,
    )
    assert res_rollback is False
    assert version_file.read_text().strip() == "2"

    # 4. Untrusted package signed with attacker key -> Rejected
    bad_priv, _ = generate_key_pair()
    pkg_attacker = tmp_path / "attacker.update"
    pack_container(new_payload, version=3, device_id=target.name, private_key=bad_priv, out_path=pkg_attacker)
    res_attacker = updater.apply_signed_update(
        container_path=pkg_attacker,
        public_key_path=pub_file,
        target=target,
        state_file=state_file,
        version_file=version_file,
    )
    assert res_attacker is False
    assert version_file.read_text().strip() == "2"
