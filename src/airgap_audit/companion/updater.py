"""
Offline USB Application Update Agent (MVP).

Runs from systemd ExecStartPre on DietPi to detect, verify, and atomically apply
binary updates from a USB flash drive.
"""

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

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [updater] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("airgap_updater")

# Defaults (can be overridden via environment variable TARGET_BIN)
TARGET_BIN = Path(os.getenv("TARGET_BIN", "/home/dietpi/lvgl_gui"))
STATE_FILE = TARGET_BIN.parent / f".{TARGET_BIN.name}_hash"
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
        data = json.loads(subprocess.run(cmd, capture_output=True, text=True, check=True).stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return []

    partitions = []
    for disk in data.get("blockdevices", []):
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
            partitions.append({"device": p.get("path") or f"/dev/{p['name']}", "mount": active_mount})

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


def apply_update(source: Path, target: Path = TARGET_BIN, state_file: Path = STATE_FILE) -> bool:
    """Atomically install new binary if SHA-256 differs from host state file."""
    new_hash = get_file_sha256(source)
    if state_file.is_file() and state_file.read_text().strip() == new_hash:
        logger.info("Binary matches previously applied hash (%s...). Skipping.", new_hash[:10])
        return False

    logger.info("New update found (SHA-256: %s...). Installing to %s", new_hash[:10], target)
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = target.with_suffix(".new")

    shutil.copy2(source, staging)
    staging.chmod(0o755)

    # Chown to target directory's owner if running as root
    if os.geteuid() == 0:
        stat = target.parent.stat()
        os.chown(staging, stat.st_uid, stat.st_gid)

    if target.is_file():
        shutil.copy2(target, target.with_suffix(".bak"))

    os.replace(staging, target)
    state_file.write_text(f"{new_hash}\n")
    logger.info("Successfully updated %s", target)
    return True


def run(target: Path = TARGET_BIN, state_file: Path = STATE_FILE) -> bool:
    """Search plugged USB drives for candidate binary and apply update."""
    devices = find_usb_partitions()
    if not devices:
        logger.info("No removable USB storage detected.")
        return False

    for dev in devices:
        try:
            with mount_usb_readonly(dev["device"], dev["mount"]) as mount_dir:
                candidate = mount_dir / target.name
                if candidate.is_file():
                    return apply_update(candidate, target=target, state_file=state_file)
        except subprocess.SubprocessError as err:
            logger.error("Failed to read USB %s: %s", dev["device"], err)

    return False


def main() -> None:
    """Systemd entry point."""
    try:
        run()
    except Exception:
        logger.exception("Unexpected error during update check")
    sys.exit(0)


if __name__ == "__main__":
    main()
