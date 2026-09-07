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

## Step 2: Cryptographic Container & Hardware Binding (CWE-494 Remediation)

### 1. What We Did & Architecture
We remediated CWE-494 by implementing a post-build signing tool and a sealed single-file container format (`<binary_name>.update`, magic `b"AGUP"`). The 136-byte cryptographic header encapsulates the format version, a monotonic counter for anti-rollback protection, a 20-byte target hardware device identifier (`"lvgl_gui"`), the payload's byte length, and its SHA-256 digest, signed with **Ed25519** (64-byte asymmetric signature). On the target device, `updater.py` validates the digital signature against a trusted public key (`/etc/airgap/public_key.pem`), verifies device binding and monotonic versioning (`version >= installed_version`), checks the payload digest, and unpacks the clean ELF binary directly to `/home/dietpi/lvgl_gui`.

```
[Developer Machine: cmake build] ──> [airgap-audit package create (Ed25519 privkey)] ──> [lvgl_gui.update]
                                                                                               │
                                    ┌────────────────── [Physical USB Mount on DietPi] ────────┘
                                    ▼
       [airgap-updater validates Ed25519 signature via /etc/airgap/public_key.pem]
            ├── FAIL: Log security error & reject update (leave host intact)
            └── PASS: Check device ID & version ──> Atomic unpack to /home/dietpi/lvgl_gui
```

### 2. The Vulnerability Remediation & Interview Takeaway
This step completely eliminates **CWE-494** and **CWE-353**. An attacker with physical USB access can no longer inject a rogue binary or modified shell script: without the private signing key, any altered payload fails the Ed25519 signature or SHA-256 check and is rejected before execution. Furthermore, monotonic version tracking prevents **firmware rollback / downgrade attacks** where an adversary tries to re-flash a legitimate older version known to contain exploitable vulnerabilities.

### 3. Verification & Tamper Resistance Proof
Verified via automated test suite across 5 attack scenarios:
```text
[PASS] Signature tampering: Bit-flipped signature rejected with SignatureError
[PASS] Payload tampering: Bit-flipped ELF bytes rejected with PayloadChecksumError
[PASS] Rogue key injection: Container signed with untrusted key rejected
[PASS] Hardware mismatch: Update targeting 'other_hw' rejected on 'lvgl_gui'
[PASS] Rollback attack: Version 1 package rejected when device is at version 2
```

---
