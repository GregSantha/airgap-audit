# Embedded Security Evolution & Interview Guide

A progressive, step-by-step breakdown of how the `airgap-audit` system evolves from a naive, vulnerable offline update mechanism into an enterprise-hardened, cryptographically verified embedded platform.

---

## Step 1: Baseline Offline USB Updater (CWE-494 / CWE-353)

### 1. What We Did & Architecture
We implemented an MVP companion update agent (`updater.py`) running inside systemd's `ExecStartPre` on DietPi (ARMv8 AArch64). When a physical USB drive is plugged in, the agent safely identifies removable block devices using `lsblk -J` (enforcing `tran == "usb"` and `rm == true` to strictly protect SD card system partitions), mounts it transiently with read-only (`ro`) flags, calculates the candidate binary's SHA-256 digest against a local state hash file (`/home/dietpi/.lvgl_gui_hash`), and performs an atomic file replacement (`.new` -> `.bak` -> `os.replace`).

```
[Physical USB inserted] ──> [lsblk JSON filter] ──> [ro transient mount]
                                                          │
   ┌──────────────────────────────────────────────────────┴───┐
   ▼                                                          ▼
[SHA-256 matches state file]                     [SHA-256 differs / new binary]
  └──> Defer update, continue boot                 └──> Atomic swap & update state
```

### 2. The Vulnerability & Educational Takeaway
While the baseline handles hardware isolation and prevents reboot loops, it completely lacks authenticity verification—exhibiting **CWE-494 (Download/Update of Code Without Integrity Check)** and **CWE-353 (Missing Support for Integrity Check)**. Any person with physical access to the device can insert an unauthenticated USB drive containing a malicious ELF binary or a backdoor shell script named `lvgl_gui`. Because `ExecStartPre` executes with root privileges to manage mounts, the untrusted binary would immediately replace the kiosk application and run at system boot.

### 3. Hardware Execution Proof
Verified on real DietPi hardware during boot:
```text
[20:45:41] [INFO] [app] Initializing Linux DRM/KMS (/dev/dri/card0)...
[20:45:41] [INFO] [app] HAL initialization complete, entering main loop
[20:45:42] [INFO] [updater] New update found (SHA-256: 5c078aef5f...). Installing to /home/dietpi/lvgl_gui
[20:45:42] [INFO] [updater] Successfully updated /home/dietpi/lvgl_gui
[20:45:42] [INFO] [systemd] Started lvgl_gui.service - LVGL GUI Application with Offline USB Updater.
```

---
