"""
Binary container packaging and verification for airgap-audit.

Defines the sealed `<target>.update` single-file container format (magic b"AGUP"),
featuring cryptographic header binding, Ed25519 signature verification,
hardware device ID binding, dual-versioning (App Version + Security Epoch),
and SHA-256 payload integrity.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from airgap_audit.core.crypto import (
    compute_sha256,
    sign_data,
    verify_signature,
)

MAGIC = b"AGUP"
SUPPORTED_HEADER_VERSION = 1
HEADER_FORMAT_SIGNED = ">4sIII20sQ32s"
HEADER_FORMAT_FULL = ">4sIII20sQ32s64s"
HEADER_SIGNED_SIZE = struct.calcsize(HEADER_FORMAT_SIGNED)  # 76 bytes
HEADER_FULL_SIZE = struct.calcsize(HEADER_FORMAT_FULL)  # 140 bytes
DEVICE_ID_MAX_LEN = 20


class ContainerError(Exception):
    """Base exception for container packaging and validation failures."""


class MagicMismatchError(ContainerError):
    """Raised when the container does not start with b'AGUP'."""


class UnsupportedHeaderVersionError(ContainerError):
    """Raised when the container header version is unsupported."""


class SignatureError(ContainerError):
    """Raised when the Ed25519 digital signature fails verification."""


class DeviceMismatchError(ContainerError):
    """Raised when the container device ID does not match the target hardware."""


class RollbackVersionError(ContainerError):
    """Raised when candidate security epoch is lower than the minimum allowed security epoch."""


class PayloadChecksumError(ContainerError):
    """Raised when the unpacked payload SHA-256 digest does not match the header."""


class TruncatedContainerError(ContainerError):
    """Raised when the container file is truncated or corrupted."""


@dataclass(frozen=True)
class ContainerHeader:
    magic: bytes
    header_version: int
    app_version: int
    security_epoch: int
    device_id: str
    payload_length: int
    payload_sha256: bytes
    signature: bytes

    @property
    def payload_sha256_hex(self) -> str:
        return self.payload_sha256.hex()

    @property
    def signature_hex(self) -> str:
        return self.signature.hex()


def _format_device_id(device_id: str) -> bytes:
    """Encode device ID to fixed 20-byte null-padded UTF-8 bytes."""
    encoded = device_id.strip().encode("utf-8")
    if len(encoded) > DEVICE_ID_MAX_LEN:
        raise ContainerError(f"Device ID '{device_id}' exceeds maximum length of {DEVICE_ID_MAX_LEN} bytes")
    return encoded.ljust(DEVICE_ID_MAX_LEN, b"\x00")


def _parse_device_id(raw_bytes: bytes) -> str:
    """Decode 20-byte null-padded bytes to string."""
    return raw_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def parse_header_bytes(header_bytes: bytes) -> tuple[ContainerHeader, bytes]:
    """
    Parse a 140-byte container header.

    Returns the ContainerHeader instance and the 76-byte signed prefix.
    """
    if len(header_bytes) < HEADER_FULL_SIZE:
        raise TruncatedContainerError(f"Header too short: expected {HEADER_FULL_SIZE} bytes, got {len(header_bytes)}")

    magic, hdr_ver, app_ver, sec_epoch, raw_dev_id, payload_len, payload_sha, sig = struct.unpack(
        HEADER_FORMAT_FULL, header_bytes[:HEADER_FULL_SIZE]
    )

    if magic != MAGIC:
        raise MagicMismatchError(f"Invalid magic bytes: expected {MAGIC!r}, got {magic!r}")

    if hdr_ver != SUPPORTED_HEADER_VERSION:
        raise UnsupportedHeaderVersionError(
            f"Unsupported header version {hdr_ver} (supported: {SUPPORTED_HEADER_VERSION})"
        )

    signed_prefix = header_bytes[:HEADER_SIGNED_SIZE]
    device_id = _parse_device_id(raw_dev_id)

    header = ContainerHeader(
        magic=magic,
        header_version=hdr_ver,
        app_version=app_ver,
        security_epoch=sec_epoch,
        device_id=device_id,
        payload_length=payload_len,
        payload_sha256=payload_sha,
        signature=sig,
    )
    return header, signed_prefix


def inspect_container(path: Path) -> ContainerHeader:
    """Inspect and return container header metadata without requiring verification."""
    if not path.is_file():
        raise FileNotFoundError(f"Container file not found: {path}")

    with open(path, "rb") as f:
        header_bytes = f.read(HEADER_FULL_SIZE)

    header, _ = parse_header_bytes(header_bytes)
    return header


def pack_container(
    payload_path: Path,
    app_version: int,
    device_id: str,
    private_key: ed25519.Ed25519PrivateKey,
    security_epoch: int = 1,
    out_path: Path | None = None,
) -> bytes:
    """
    Package an ELF binary into a signed .update container with dual versioning.

    Writes to out_path if provided, and returns the full container bytes.
    """
    if not payload_path.is_file():
        raise FileNotFoundError(f"Payload file not found: {payload_path}")

    if app_version < 0 or security_epoch < 0:
        raise ValueError("App version and security epoch must be non-negative integers")

    payload_bytes = payload_path.read_bytes()
    payload_length = len(payload_bytes)
    payload_sha256 = compute_sha256(payload_bytes)

    dev_id_bytes = _format_device_id(device_id)

    # Pack the 76-byte signed header prefix
    signed_prefix = struct.pack(
        HEADER_FORMAT_SIGNED,
        MAGIC,
        SUPPORTED_HEADER_VERSION,
        app_version,
        security_epoch,
        dev_id_bytes,
        payload_length,
        payload_sha256,
    )

    # Sign the 76-byte prefix with Ed25519
    signature = sign_data(private_key, signed_prefix)

    # Assemble complete container: 76-byte prefix + 64-byte signature + payload
    container_bytes = signed_prefix + signature + payload_bytes

    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(container_bytes)

    return container_bytes


def unpack_and_verify(
    container_path: Path,
    public_key: ed25519.Ed25519PublicKey,
    expected_device_id: str | None = None,
    min_epoch: int = 0,
) -> tuple[bytes, ContainerHeader]:
    """
    Verify container authenticity, hardware binding, security epoch, and payload integrity.

    Returns the unpacked payload bytes and the validated ContainerHeader.
    """
    if not container_path.is_file():
        raise FileNotFoundError(f"Container file not found: {container_path}")

    with open(container_path, "rb") as f:
        header_bytes = f.read(HEADER_FULL_SIZE)
        header, signed_prefix = parse_header_bytes(header_bytes)

        # 1. Verify Ed25519 signature
        if not verify_signature(public_key, header.signature, signed_prefix):
            raise SignatureError("Ed25519 signature verification failed: container is untrusted or tampered")

        # 2. Check Device ID
        if expected_device_id and header.device_id != expected_device_id:
            raise DeviceMismatchError(
                f"Device ID mismatch: container targets '{header.device_id}', expected '{expected_device_id}'"
            )

        # 3. Check anti-rollback on Security Epoch
        if header.security_epoch < min_epoch:
            raise RollbackVersionError(
                f"Rollback rejected: candidate security epoch {header.security_epoch} < "
                f"minimum required security epoch {min_epoch} (CWE-1328 protection)"
            )

        # 4. Stream and verify payload
        payload_bytes = f.read()
        if len(payload_bytes) != header.payload_length:
            raise TruncatedContainerError(
                f"Payload size mismatch: expected {header.payload_length} bytes, got {len(payload_bytes)}"
            )

        actual_sha = compute_sha256(payload_bytes)
        if actual_sha != header.payload_sha256:
            raise PayloadChecksumError(
                f"Payload checksum mismatch: expected {header.payload_sha256_hex}, got {actual_sha.hex()}"
            )

    return payload_bytes, header
