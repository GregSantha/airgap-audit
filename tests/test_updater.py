import hashlib
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from airgap_audit.companion.updater import (
    apply_update,
    find_usb_partitions,
    get_file_sha256,
    mount_usb_readonly,
    run,
)

# Real JSON dump captured from DietPi on ARMv8
REAL_DIETPI_LSBLK_JSON = """{
   "blockdevices": [
      {
         "name": "sda",
         "path": "/dev/sda",
         "tran": "usb",
         "rm": true,
         "fstype": null,
         "mountpoints": [],
         "mountpoint": null,
         "children": [
            {
               "name": "sda1",
               "path": "/dev/sda1",
               "tran": null,
               "rm": true,
               "fstype": "vfat",
               "mountpoints": [],
               "mountpoint": null
            }
         ]
      },{
         "name": "mmcblk0",
         "path": "/dev/mmcblk0",
         "tran": "mmc",
         "rm": false,
         "fstype": null,
         "mountpoints": [],
         "mountpoint": null,
         "children": [
            {
               "name": "mmcblk0p1",
               "path": "/dev/mmcblk0p1",
               "tran": "mmc",
               "rm": false,
               "fstype": "vfat",
               "mountpoints": [
                   "/boot/firmware"
               ],
               "mountpoint": "/boot/firmware"
            },{
               "name": "mmcblk0p2",
               "path": "/dev/mmcblk0p2",
               "tran": "mmc",
               "rm": false,
               "fstype": "ext4",
               "mountpoints": [
                   "/"
               ],
               "mountpoint": "/"
            }
         ]
      }
   ]
}"""


def test_get_file_sha256(tmp_path: Path) -> None:
    sample = tmp_path / "app.bin"
    sample.write_bytes(b"HELLO_ARMV8_LVGL")
    expected = hashlib.sha256(b"HELLO_ARMV8_LVGL").hexdigest()
    assert get_file_sha256(sample) == expected


def test_find_usb_partitions_real_dietpi_hardware(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify partition discovery against the exact lsblk JSON from the physical DietPi device."""
    def mock_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=["lsblk"], returncode=0, stdout=REAL_DIETPI_LSBLK_JSON)

    monkeypatch.setattr(subprocess, "run", mock_run)
    partitions = find_usb_partitions()

    # Must accurately find /dev/sda1 and ignore internal SD card mmcblk0p1 & mmcblk0p2
    assert len(partitions) == 1
    assert partitions[0]["device"] == "/dev/sda1"
    assert partitions[0]["mount"] is None


def test_mount_usb_readonly_context(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # 1. Existing mount
    existing = tmp_path / "media_usb"
    existing.mkdir()
    with mount_usb_readonly("/dev/sda1", str(existing)) as p:
        assert p == existing

    # 2. Transient mount
    mock_run = MagicMock()
    monkeypatch.setattr(subprocess, "run", mock_run)
    with mount_usb_readonly("/dev/sda1", None) as p:
        assert p == Path("/tmp/airgap_usb")
        mock_run.assert_any_call(["mount", "-o", "ro", "/dev/sda1", "/tmp/airgap_usb"], check=True)


def test_apply_update_lifecycle(tmp_path: Path) -> None:
    target = tmp_path / "lvgl_gui"
    state_file = tmp_path / ".hash"
    source = tmp_path / "new_lvgl_gui"

    # 1. Initial install
    source.write_bytes(b"V1_BINARY")
    assert apply_update(source, target=target, state_file=state_file) is True
    assert target.read_bytes() == b"V1_BINARY"
    assert state_file.read_text().strip() == get_file_sha256(source)

    # 2. Re-run with same binary -> skipped
    assert apply_update(source, target=target, state_file=state_file) is False

    # 3. Update with new binary -> backup created and replaced
    source.write_bytes(b"V2_BINARY")
    assert apply_update(source, target=target, state_file=state_file) is True
    assert target.read_bytes() == b"V2_BINARY"
    assert target.with_suffix(".bak").read_bytes() == b"V1_BINARY"


def test_run_empty_usb(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("airgap_audit.companion.updater.find_usb_partitions", list)
    assert run() is False
