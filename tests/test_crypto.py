"""Unit tests for cryptographic primitives (Ed25519 and SHA-256)."""

from pathlib import Path

import pytest

from airgap_audit.core.crypto import (
    compute_sha256,
    compute_sha256_hex,
    generate_key_pair,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
    sign_data,
    verify_signature,
)


def test_key_generation_and_pem_roundtrip(tmp_path: Path) -> None:
    priv, pub = generate_key_pair()
    priv_file = tmp_path / "priv.pem"
    pub_file = tmp_path / "pub.pem"

    save_private_key(priv, priv_file)
    save_public_key(pub, pub_file)

    loaded_priv = load_private_key(priv_file)
    loaded_pub = load_public_key(pub_file)

    test_message = b"embedded-security-payload-test"
    sig = sign_data(loaded_priv, test_message)
    assert verify_signature(loaded_pub, sig, test_message) is True


def test_private_key_permissions(tmp_path: Path) -> None:
    priv, _ = generate_key_pair()
    priv_file = tmp_path / "priv.pem"
    save_private_key(priv, priv_file)

    # Verify mode is 0600 (owner read/write only)
    mode = priv_file.stat().st_mode & 0o777
    assert mode == 0o600


def test_streaming_sha256(tmp_path: Path) -> None:
    data = b"x" * 150000  # > 2 chunks of 64KB
    test_file = tmp_path / "large.bin"
    test_file.write_bytes(data)

    digest_bytes = compute_sha256(test_file)
    digest_hex = compute_sha256_hex(test_file)

    assert len(digest_bytes) == 32
    assert len(digest_hex) == 64
    assert digest_bytes.hex() == digest_hex
    assert digest_bytes == compute_sha256(data)


def test_sign_and_verify_valid() -> None:
    priv, pub = generate_key_pair()
    payload = b"valid firmware binary ELF data"
    sig = sign_data(priv, payload)

    assert len(sig) == 64
    assert verify_signature(pub, sig, payload) is True


def test_verify_tampered_signature() -> None:
    priv, pub = generate_key_pair()
    payload = b"valid payload"
    sig = bytearray(sign_data(priv, payload))
    sig[0] ^= 0xFF  # Tamper with signature

    assert verify_signature(pub, bytes(sig), payload) is False


def test_verify_tampered_data() -> None:
    priv, pub = generate_key_pair()
    payload = b"valid payload"
    sig = sign_data(priv, payload)

    assert verify_signature(pub, sig, b"tampered payload") is False


def test_verify_wrong_key() -> None:
    priv1, _ = generate_key_pair()
    _, pub2 = generate_key_pair()
    payload = b"payload"
    sig = sign_data(priv1, payload)

    assert verify_signature(pub2, sig, payload) is False


def test_load_nonexistent_keys(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_private_key(tmp_path / "nonexistent.pem")

    with pytest.raises(FileNotFoundError):
        load_public_key(tmp_path / "nonexistent.pem")
