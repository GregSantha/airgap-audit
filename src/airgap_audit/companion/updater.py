"""
Offline USB Application Update Agent.

Designed to be executed before launching the main application (e.g. via systemd ExecStartPre
on DietPi) to detect, verify, and atomically apply signed update bundles.
"""

from pathlib import Path


def run_update(
    usb_mount: Path,
    target_binary: Path,
    pubkey_path: Path,
    bundle_name: str = "update.fwup",
) -> bool:
    """
    Search for an update container on the USB drive, verify its cryptographic
    integrity (Ed25519 signature and SHA-256 payload digest), and atomically stage it.

    Args:
        usb_mount: Mount path of the pendrive (e.g. /media/usb or /mnt/usb).
        target_binary: Destination path of the running executable (e.g. /usr/local/bin/lvgl_gui).
        pubkey_path: Path to trusted Ed25519 public key stored on the read-only or secure partition.
        bundle_name: Name of the expected container file on the pendrive.

    Returns:
        True if an update was verified and applied, False if no update was present.

    Raises:
        NotImplementedError: Implementation will be added incrementally in Step 1.
    """
    raise NotImplementedError(
        "Offline USB updater logic is not implemented yet (scheduled for Step 1)."
    )


def main() -> None:
    """CLI entrypoint for standalone or systemd invocation."""
    run_update(
        usb_mount=Path("/media/usb"),
        target_binary=Path("/usr/local/bin/lvgl_gui"),
        pubkey_path=Path("/etc/airgap-audit/pubkey.pem"),
    )


if __name__ == "__main__":
    main()
