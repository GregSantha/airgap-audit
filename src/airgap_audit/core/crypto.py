"""
Cryptographic primitives for airgap-audit using Ed25519 and SHA-256.

Provides key generation, PEM serialization/loading, streaming hashing,
and digital signature creation and verification.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class CryptoError(Exception):
    """Base exception for cryptographic failures."""


class SignatureVerificationError(CryptoError):
    """Raised when digital signature verification fails."""


def generate_key_pair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a new Ed25519 private and public key pair."""
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def save_private_key(
    key: ed25519.Ed25519PrivateKey,
    path: Path,
    password: str | None = None,
) -> None:
    """Save an Ed25519 private key to a PEM file with restricted permissions (0600)."""
    encryption: serialization.KeySerializationEncryption
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()

    pem_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    # Write with restricted permissions
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(fd, "wb") as f:
        f.write(pem_bytes)


def save_public_key(key: ed25519.Ed25519PublicKey, path: Path) -> None:
    """Save an Ed25519 public key to a PEM file."""
    pem_bytes = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem_bytes)


def load_private_key(
    path: Path,
    password: str | None = None,
) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM file."""
    if not path.is_file():
        raise FileNotFoundError(f"Private key file not found: {path}")

    pem_bytes = path.read_bytes()
    pwd_bytes = password.encode("utf-8") if password else None
    try:
        loaded = serialization.load_pem_private_key(pem_bytes, password=pwd_bytes)
    except Exception as exc:
        raise CryptoError(f"Failed to load private key from {path}: {exc}") from exc

    if not isinstance(loaded, ed25519.Ed25519PrivateKey):
        raise CryptoError(f"Key in {path} is not an Ed25519 private key")

    return loaded


def load_public_key(path: Path) -> ed25519.Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file."""
    if not path.is_file():
        raise FileNotFoundError(f"Public key file not found: {path}")

    pem_bytes = path.read_bytes()
    try:
        loaded = serialization.load_pem_public_key(pem_bytes)
    except Exception as exc:
        raise CryptoError(f"Failed to load public key from {path}: {exc}") from exc

    if not isinstance(loaded, ed25519.Ed25519PublicKey):
        raise CryptoError(f"Key in {path} is not an Ed25519 public key")

    return loaded


def compute_sha256(data_or_path: bytes | Path) -> bytes:
    """Compute raw 32-byte SHA-256 digest from bytes or file path (streaming)."""
    hasher = hashlib.sha256()
    if isinstance(data_or_path, Path):
        with open(data_or_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
    else:
        hasher.update(data_or_path)
    return hasher.digest()


def compute_sha256_hex(data_or_path: bytes | Path) -> str:
    """Compute 64-character hex SHA-256 digest."""
    return compute_sha256(data_or_path).hex()


def sign_data(private_key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    """Sign raw bytes with Ed25519 private key, returning 64-byte signature."""
    return private_key.sign(data)


def verify_signature(
    public_key: ed25519.Ed25519PublicKey,
    signature: bytes,
    data: bytes,
) -> bool:
    """
    Verify Ed25519 signature over data.

    Returns True if valid, False if signature is invalid.
    """
    if len(signature) != 64:
        return False
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False
