"""
Offline USB Application Update Agent (ARMv8 / DietPi).

Runs from systemd ExecStartPre to detect, verify (via Ed25519 digital signature,
hardware binding, security epoch anti-rollback), and atomically apply binary updates from USB.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from airgap_audit.core.container import (
    ContainerError,
    unpack_and_verify,
)
from airgap_audit.core.crypto import (
    CryptoError,
    load_public_key,
)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [updater] %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
    force=True,
)
logger = logging.getLogger("airgap_updater")

# Defaults (can be overridden via environment variables)
TARGET_BIN = Path(os.getenv("TARGET_BIN", "/home/dietpi/lvgl_gui"))
STATE_FILE = TARGET_BIN.parent / f".{TARGET_BIN.name}_hash"
VERSION_FILE = TARGET_BIN.parent / f".{TARGET_BIN.name}_version"
EPOCH_FILE = TARGET_BIN.parent / f".{TARGET_BIN.name}_epoch"
PUBLIC_KEY_PATH = Path(os.getenv("AIRGAP_PUBLIC_KEY", "/etc/airgap/public_key.pem"))
TEMP_MOUNT = Path("/tmp/airgap_usb")
SUPPORTED_FS = {"vfat", "fat", "exfat", "ext4"}


def get_file_sha256(path: Path) -> str:
    """Compute SHA-256 digest in 64KB memory-safe chunks."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def find_usb_partitions() -> list[dict[str, Any]]:
    """Discover removable USB partitions via lsblk, ignoring internal SD/system disks."""
    cmd = ["lsblk", "-J", "-o", "NAME,PATH,TRAN,RM,FSTYPE,MOUNTPOINTS,MOUNTPOINT"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(proc.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError) as exc:
        logger.warning("lsblk command failed or returned invalid JSON: %s", exc)
        return []

    partitions = []
    block_devices = data.get("blockdevices", [])
    for disk in block_devices:
        is_usb = disk.get("tran") == "usb"
        is_removable = disk.get("rm") in (True, 1, "1")
        if not (is_usb and is_removable):
            continue

        # Check partitions (e.g. sda -> sda1) or whole disk if unpartitioned
        parts = disk.get("children", [disk])
        for p in parts:
            fstype = (p.get("fstype") or "").lower()
            if fstype not in SUPPORTED_FS:
                continue

            mounts = p.get("mountpoints") or [p.get("mountpoint")]
            if any(m in ("/", "/boot", "/boot/firmware") for m in mounts if m):
                continue

            active_mount = next((m for m in mounts if m), None)
            dev_path = p.get("path") or f"/dev/{p['name']}"
            partitions.append({"device": dev_path, "mount": active_mount})
            logger.info("Detected removable USB partition: %s (fs=%s, mount=%s)", dev_path, fstype, active_mount)

    return partitions


@contextmanager
def mount_usb_readonly(device: str, existing_mount: str | None) -> Generator[Path]:
    """Provide read-only access to a USB drive (existing mount or transient /tmp mount)."""
    if existing_mount and Path(existing_mount).is_dir():
        yield Path(existing_mount)
        return

    TEMP_MOUNT.mkdir(parents=True, exist_ok=True)
    subprocess.run(["mount", "-o", "ro", device, str(TEMP_MOUNT)], check=True)
    try:
        yield TEMP_MOUNT
    finally:
        subprocess.run(["umount", str(TEMP_MOUNT)], capture_output=True, check=False)
        shutil.rmtree(TEMP_MOUNT, ignore_errors=True)


def get_current_installed_version(version_file: Path = VERSION_FILE) -> int:
    """Read the currently installed feature version number (defaults to 0)."""
    if version_file.is_file():
        try:
            return int(version_file.read_text().strip())
        except ValueError:
            logger.warning("Corrupted version file at %s, treating as 0", version_file)
            return 0
    return 0


def get_current_security_epoch(epoch_file: Path = EPOCH_FILE) -> int:
    """Read the currently installed security epoch (defaults to 0)."""
    if epoch_file.is_file():
        try:
            return int(epoch_file.read_text().strip())
        except ValueError:
            logger.warning("Corrupted epoch file at %s, treating as 0", epoch_file)
            return 0
    return 0


def apply_update(source: Path, target: Path = TARGET_BIN, state_file: Path = STATE_FILE) -> bool:
    """Atomically install binary if SHA-256 differs from host state file (legacy/unauthenticated)."""
    new_hash = get_file_sha256(source)
    if state_file.is_file() and state_file.read_text().strip() == new_hash:
        logger.info("Binary matches previously applied hash (%s...). Skipping.", new_hash[:10])
        return False

    logger.info("New update found (SHA-256: %s...). Installing to %s", new_hash[:10], target)
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = target.with_suffix(".new")

    shutil.copy2(source, staging)
    staging.chmod(0o755)

    if os.geteuid() == 0:
        stat = target.parent.stat()
        os.chown(staging, stat.st_uid, stat.st_gid)

    if target.is_file():
        shutil.copy2(target, target.with_suffix(".bak"))

    os.replace(staging, target)
    state_file.write_text(f"{new_hash}\n")
    logger.info("Successfully updated %s", target)
    return True


def apply_signed_update(
    container_path: Path,
    public_key_path: Path = PUBLIC_KEY_PATH,
    target: Path = TARGET_BIN,
    state_file: Path = STATE_FILE,
    version_file: Path = VERSION_FILE,
    epoch_file: Path = EPOCH_FILE,
) -> bool:
    """
    Verify and atomically apply a signed .update container package.

    Enforces:
    1. Public key presence and Ed25519 signature validity.
    2. Target hardware device ID matching.
    3. Security Epoch anti-rollback (candidate epoch >= current epoch).
    4. Allows feature version rollbacks within the same security epoch.
    5. Payload integrity check (SHA-256).
    """
    if not public_key_path.is_file():
        logger.error(
            "Public key missing at %s. Refusing to install unverified update (fail-safe).",
            public_key_path,
        )
        return False

    try:
        public_key = load_public_key(public_key_path)
    except CryptoError as err:
        logger.error("Failed to load public key: %s", err)
        return False

    current_epoch = get_current_security_epoch(epoch_file)
    current_version = get_current_installed_version(version_file)

    try:
        payload_bytes, header = unpack_and_verify(
            container_path=container_path,
            public_key=public_key,
            expected_device_id=target.name,
            min_epoch=current_epoch,
        )
    except ContainerError as err:
        logger.error("Security verification failed for %s: %s", container_path, err)
        return False

    # Prevent redundant write cycles if same epoch, version, and binary hash already installed
    if (
        header.security_epoch == current_epoch
        and header.app_version == current_version
        and state_file.is_file()
        and state_file.read_text().strip() == header.payload_sha256_hex
    ):
        logger.info(
            "Package %s matches installed version (App: %d, Epoch: %d) and hash (%s...). Skipping.",
            container_path.name,
            current_version,
            current_epoch,
            header.payload_sha256_hex[:10],
        )
        return False

    logger.info(
        "Verified update: App Version %d, Epoch %d (current Epoch %d), device '%s', SHA-256 %s... Installing to %s",
        header.app_version,
        header.security_epoch,
        current_epoch,
        header.device_id,
        header.payload_sha256_hex[:10],
        target,
    )

    # Atomic write sequence:
    # 1. Write to target.new
    # 2. chmod 0755
    # 3. Chown to target directory's owner (if running as root)
    # 4. Copy current target to target.bak
    # 5. os.replace(staging, target)
    # 6. Update version, epoch, and hash state files
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = target.with_suffix(".new")
    staging.write_bytes(payload_bytes)
    staging.chmod(0o755)

    if os.geteuid() == 0:
        stat = target.parent.stat()
        os.chown(staging, stat.st_uid, stat.st_gid)

    if target.is_file():
        shutil.copy2(target, target.with_suffix(".bak"))

    os.replace(staging, target)
    state_file.write_text(f"{header.payload_sha256_hex}\n")
    version_file.write_text(f"{header.app_version}\n")
    epoch_file.write_text(f"{header.security_epoch}\n")

    logger.info(
        "Successfully updated %s to App Version %d (Security Epoch %d)",
        target,
        header.app_version,
        header.security_epoch,
    )
    return True


def run(
    target: Path = TARGET_BIN,
    state_file: Path = STATE_FILE,
    version_file: Path = VERSION_FILE,
    epoch_file: Path = EPOCH_FILE,
    public_key_path: Path = PUBLIC_KEY_PATH,
) -> bool:
    """Search plugged USB drives for signed package (<target>.update) and apply update."""
    logger.info("=== AirGap Offline USB Companion Updater Check ===")
    logger.info(
        "Target: %s (installed version: %d, epoch: %d)",
        target,
        get_current_installed_version(version_file),
        get_current_security_epoch(epoch_file),
    )
    logger.info("Public key: %s (exists=%s)", public_key_path, public_key_path.is_file())

    devices = find_usb_partitions()
    if not devices:
        logger.info("No removable USB storage detected on system.")
        return False

    update_pkg_name = f"{target.name}.update"

    for dev in devices:
        try:
            with mount_usb_readonly(dev["device"], dev["mount"]) as mount_dir:
                candidate = mount_dir / update_pkg_name
                logger.info("Checking %s for '%s'...", dev["device"], update_pkg_name)
                if candidate.is_file():
                    logger.info(
                        "Found update package: %s (%d bytes). Verifying signature...",
                        candidate,
                        candidate.stat().st_size,
                    )
                    return apply_signed_update(
                        container_path=candidate,
                        public_key_path=public_key_path,
                        target=target,
                        state_file=state_file,
                        version_file=version_file,
                        epoch_file=epoch_file,
                    )
                else:
                    try:
                        found_files = [f.name for f in mount_dir.iterdir() if not f.name.startswith(".")]
                        logger.warning(
                            "'%s' not found on %s. Root files on USB: %s",
                            update_pkg_name,
                            dev["device"],
                            found_files[:10],
                        )
                    except OSError as read_err:
                        logger.warning("Could not list directory contents of %s: %s", mount_dir, read_err)
        except subprocess.SubprocessError as err:
            logger.error("Failed to mount or read USB %s: %s", dev["device"], err)

    return False


def main() -> None:
    """Systemd entry point."""
    try:
        run()
    except Exception:
        logger.exception("Fatal error during USB update check")
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
    sys.exit(0)


if __name__ == "__main__":
    main()
