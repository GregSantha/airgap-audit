from pathlib import Path

import pytest

import airgap_audit
from airgap_audit.companion.updater import run_update


def test_package_metadata() -> None:
    assert airgap_audit.__version__ == "0.1.0"


def test_updater_stub_raises_not_implemented() -> None:
    with pytest.raises(NotImplementedError) as exc_info:
        run_update(
            usb_mount=Path("/tmp/mock_usb"),
            target_binary=Path("/tmp/mock_target"),
            pubkey_path=Path("/tmp/mock_pubkey"),
        )
    assert "not implemented yet" in str(exc_info.value)
