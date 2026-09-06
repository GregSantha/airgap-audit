import airgap_audit
from airgap_audit.companion.updater import run


def test_package_metadata() -> None:
    assert airgap_audit.__version__ == "0.1.0"

def test_run_clean_exit() -> None:
    # Safe fallback when no USB is present
    assert run() is False
