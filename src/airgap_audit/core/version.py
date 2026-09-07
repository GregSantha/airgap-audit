"""
Version management and header parsing utilities for airgap-audit.

Provides semver-to-integer conversion and single-source-of-truth extraction
from C++ version.h headers.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def semver_to_code(version_str: str) -> int:
    """
    Convert semantic version string to a monotonic integer code.

    Examples:
        '0.1.0' -> 100 (0*10000 + 1*100 + 0)
        '1.2.3' -> 10203 (1*10000 + 2*100 + 3)
        '2.0'   -> 20000 (2*10000 + 0*100 + 0)
        '100'   -> 100
    """
    cleaned = version_str.strip().lstrip("vV")
    parts = cleaned.split(".")
    if len(parts) >= 2:
        try:
            major = int(parts[0])
            minor = int(parts[1])
            patch = int(parts[2]) if len(parts) > 2 else 0
            return major * 10000 + minor * 100 + patch
        except ValueError:
            pass

    try:
        return int(cleaned)
    except ValueError as err:
        raise ValueError(f"Cannot parse version '{version_str}' into integer code") from err


def parse_version_header(header_path: Path) -> dict[str, Any]:
    """
    Parse C++ version.h header to extract VERSION, SECURITY_EPOCH, and DEVICE_ID.
    """
    if not header_path.is_file():
        raise FileNotFoundError(f"Version header not found: {header_path}")

    content = header_path.read_text(encoding="utf-8")

    # Match constexpr const char* VERSION = "0.1.0";
    ver_match = re.search(r'VERSION\s*=\s*"([^"]+)"', content)
    # Match constexpr unsigned int SECURITY_EPOCH = 1;
    epoch_match = re.search(r"SECURITY_EPOCH\s*=\s*(\d+)", content)
    # Match constexpr const char* DEVICE_ID = "lvgl_gui";
    dev_match = re.search(r'DEVICE_ID\s*=\s*"([^"]+)"', content)

    if not ver_match:
        raise ValueError(f"Could not find VERSION in {header_path}")

    raw_version = ver_match.group(1)
    version_code = semver_to_code(raw_version)
    security_epoch = int(epoch_match.group(1)) if epoch_match else 1
    device_id = dev_match.group(1) if dev_match else "lvgl_gui"

    return {
        "version_str": raw_version,
        "version_code": version_code,
        "security_epoch": security_epoch,
        "device_id": device_id,
        "header_path": header_path,
    }


def find_version_header(hint_path: Path | None = None) -> Path | None:
    """
    Attempt to locate version.h from hint path or common workspace directories.
    """
    candidates = []
    if hint_path:
        # If hint_path is payload: e.g. lvgl_gui/build/arm64-release/lvgl_gui -> lvgl_gui/version.h
        candidates.extend(
            [
                hint_path.parent / "version.h",
                hint_path.parent.parent / "version.h",
                hint_path.parent.parent.parent / "version.h",
            ]
        )

    candidates.extend(
        [
            Path("lvgl_gui/version.h"),
            Path("../lvgl_gui/version.h"),
            Path("version.h"),
        ]
    )

    for c in candidates:
        if c.is_file():
            return c.resolve()

    return None
