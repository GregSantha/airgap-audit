import hashlib
import json
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


def test_get_file_sha256(tmp_path: Path) -> None:
    sample = tmp_path / "app.bin"
    sample.write_bytes(b"HELLO_ARMV8_LVGL")
    expected = hashlib.sha256(b"HELLO_ARMV8_LVGL").hexdigest()
    assert get_file_sha256(sample) == expected


def test_find_usb_partitions_filtering(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_data = {
        "blockdevices": [
            {
                "name": "sda",
                "tran": "usb",
                "rm": True,
                "children": [
                    {
                        "name": "sda1",
                        "path": "/dev/sda1",
                        "fstype": "vfat",
                        "mountpoint": None,
                    }
                ],
            },
            {
                "name": "mmcblk0",
                "tran": "mmc",
                "rm": False,
                "children": [
                    {
                        "name": "mmcblk0p1",
                        "fstype": "vfat",
                        "mountpoint": "/boot/firmware",
                    },
                    {
                        "name": "mmcblk0p2",
                        "fstype": "ext4",
                        "mountpoint": "/",
                    },
                ],
            },
        ]
    }

    def mock_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=json.dumps(mock_data))

    monkeypatch.setattr(subprocess, "run", mock_run)
    partitions = find_usb_partitions()
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
