# Embedded Security Evolution & Guide

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

### 2. The Vulnerability & Takeaway
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

## Step 2: Cryptographic Container & Security Epoch Versioning (CWE-494 / CWE-1328 Remediation)

### 1. What We Did & Architecture
We remediated CWE-494 by implementing a post-build signing tool and a sealed single-file container format (`<binary_name>.update`, magic `b"AGUP"`). The 140-byte cryptographic header encapsulates format metadata, a 20-byte target hardware device identifier (`"lvgl_gui"`), the payload's byte length, its SHA-256 digest, and an asymmetric **Ed25519** signature covering the header fields. Crucially, the container implements an industry-standard **Security Epoch (Anti-Rollback) Versioning Model**:
* **App Version (Feature Version):** Identifies the user-space feature release. Moving between feature versions within the same security epoch (upgrading or rolling back during lab/QA validation) is permitted.
* **Security Epoch (Anti-Rollback Index):** Monotonically enforced counter. Incremented *only* when a security vulnerability (CWE) is resolved. The updater rejects any candidate where `security_epoch < installed_epoch`.
* **Single Source of Truth (`version.h`):** Defined cleanly in `lvgl_gui/version.h` (`VERSION`, `SECURITY_EPOCH`, `DEVICE_ID`). The Python packaging tool auto-detects this header and deterministically maps SemVer strings (`"0.1.0"` $\to$ `100`) to integer version codes without redundant manual flags.

```
[Developer Machine: cmake build] ──> [airgap-audit package create (Ed25519 privkey)] ──> [lvgl_gui.update]
                                                                                               │
                                    ┌────────────────── [Physical USB Mount on DietPi] ────────┘
                                    ▼
       [airgap-updater validates Ed25519 signature via /etc/airgap/public_key.pem]
            ├── FAIL: Log security error & reject update (leave host intact)
            └── PASS: Check device ID & Security Epoch ──> Atomic unpack to /home/dietpi/lvgl_gui
```

### 2. The Vulnerability Remediation & Takeaway
This step eliminates **CWE-494** (Unauthenticated Code Download) and **CWE-1328** (Downgrade / Rollback to Vulnerable Version). Without the private key, an adversary cannot forge valid containers.

Furthermore, **Security Epoch Versioning** solves a critical operational friction in embedded engineering:
* **Lab Testing vs. Vulnerability Fixes:** If release `1.1.0` (Epoch 1) has a UI bug during bench testing, engineers can immediately rollback to `1.0.0` (Epoch 1) via USB.
* **Irreversible Vulnerability Remediation:** When a security flaw is identified in `1.1.0`, we release `1.1.1` with `Security Epoch = 2`. Because the anti-rollback rule enforces `candidate_epoch >= installed_epoch`, an attacker with physical USB access can never downgrade the device back to the vulnerable `1.1.0` or `1.0.0` build.

### 3. Verification & Tamper Resistance Proof
Verified via automated test suite across 6 verification scenarios:
```text
[PASS] Signature tampering: Bit-flipped signature rejected with SignatureError
[PASS] Payload tampering: Bit-flipped ELF bytes rejected with PayloadChecksumError
[PASS] Rogue key injection: Container signed with untrusted key rejected
[PASS] Hardware mismatch: Update targeting 'other_hw' rejected on 'lvgl_gui'
[PASS] Feature rollback in same epoch: Downgrading v1.1.0 to v1.0.0 (Epoch 1) succeeds
[PASS] Security epoch rollback: Flashing Epoch 1 package when device is at Epoch 2 is rejected
```

---

## Step 3: Binary Mitigation Auditor (pyelftools / checksec)

### 1. What We Did & Architecture
We implemented an embedded ELF binary exploit mitigation auditor using `pyelftools` (`src/airgap_audit/audit/`). The auditor inspects compiled ARM64 ELF executables (like `lvgl_gui`) to verify that essential compile-time and link-time exploit mitigations are actively enforced, mapping deficiencies directly to CWE categories:

* **NX / DEP (No-Execute Stack - CWE-119):** Evaluates `PT_GNU_STACK` segment flags to ensure stack memory is strictly Non-Executable (`RW`, not `RWE`), blocking shellcode injection.
* **PIE / ASLR (Position Independent Executable - CWE-119):** Verifies ELF `e_type == ET_DYN` and `DT_DEBUG` to ensure randomized virtual base addresses, mitigating Return-Oriented Programming (ROP) and ret2libc attacks.
* **Stack Canary / SSP (CWE-121):** Inspects symbol tables (`.symtab`, `.dynsym`) for `__stack_chk_fail` to guard function stack frames against buffer overflow hijacking.
* **Full RELRO (Read-Only Relocations - CWE-123):** Validates `PT_GNU_RELRO` program header AND `DT_BIND_NOW` / `DF_1_NOW` flags to guarantee that the Global Offset Table (GOT) is completely resolved at startup and marked read-only, preventing GOT overwrite exploits.
* **FORTIFY_SOURCE (CWE-120 / CWE-134):** Discovers bounds-checked standard library calls (`*_chk`) to protect format string and buffer operations.
* **RPATH / RUNPATH Sanitization (CWE-426):** Scans dynamic tags for insecure search paths (such as relative paths `./`, or writable directories like `/tmp`) that permit shared library hijacking.
* **Hermetic Build Hardening:** Codified explicit flags into `lvgl_gui/CMakeLists.txt` (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3`, `-fPIE`, `-Wl,-z,relro,-z,now`, `-Wl,-z,noexecstack`) ensuring builds are hardened regardless of host cross-compiler defaults.
* **CI/CD & Packaging Gating:** Integrated `airgap-audit audit elf --strict` and `airgap-audit package create --audit` to gate release artifacts and prevent releasing unhardened binaries to field devices.

```
[Target ELF: lvgl_gui] ──> [pyelftools: Segments, Dynamic, Symbols]
                                      │
                                      ▼
                        [ElfAuditor Security Analysis]
    ├── NX Stack (PT_GNU_STACK)          ──> CWE-119 (PASS)
    ├── PIE / ASLR (ET_DYN + DT_DEBUG)   ──> CWE-119 (PASS)
    ├── Stack Canary (__stack_chk_fail)  ──> CWE-121 (PASS)
    ├── Full RELRO (PT_GNU_RELRO + NOW)  ──> CWE-123 (PASS)
    ├── FORTIFY_SOURCE (*_chk symbols)   ──> CWE-120 (PASS)
    └── RPATH / RUNPATH Sanitization     ──> CWE-426 (PASS)
                                      │
                                      ▼
          [Hardening Score: 100% | Production Status: PASSED]
          [CI/CD Release Gate & Container Pre-flight Verification]
```

### 2. The Vulnerabilities & Takeaways

| Vulnerability / Missing Mitigation | Exploitation Risk | CWE | Enforced Fix |
| :--- | :--- | :--- | :--- |
| **Executable Stack (`RWE`)** | Attacker writes shellcode to stack buffer and redirects execution directly to it. | **CWE-119** | `-Wl,-z,noexecstack` |
| **Fixed Base Address (`ET_EXEC`)** | Predictable memory layout allows reliable ROP chains and ret2libc gadgets. | **CWE-119** | `-fPIE -pie` |
| **Unprotected Stack Frames** | Buffer overflow overwrites return address on stack; control flow diverted upon function return. | **CWE-121** | `-fstack-protector-strong` |
| **Partial RELRO (Writable GOT)** | Attacker overwrites function pointers in the Global Offset Table to hijack subsequent calls. | **CWE-123** | `-Wl,-z,relro,-z,now` |
| **Unfortified libc Calls** | Out-of-bounds `memcpy`/`strcpy` or `%n` format string write vulnerabilities. | **CWE-120** / **CWE-134** | `-D_FORTIFY_SOURCE=3` |
| **Insecure RPATH (`./`)** | Attacker drops malicious `.so` into application directory; loaded preferentially on startup. | **CWE-426** | Remove relative RPATH |

### 3. Verification & Real Binary Audit Proof
Verified on real compiled ARM64 binary:
```text
$ airgap-audit audit elf lvgl_gui/build/arm64-release/lvgl_gui
Target: lvgl_gui/build/arm64-release/lvgl_gui
Architecture: AArch64 (64-bit little-endian)
File Size: 1,208,952 bytes
SHA-256: 9ba0abbebbff7de31116981ebbed33b1ff49a829b18af2a1287259fe104c9482

Mitigation                 Status  CWE      Summary
NX Stack Protection        PASS    CWE-119  Stack is non-executable (NX enabled).
PIE / ASLR                 PASS    CWE-119  Full Position Independent Executable (PIE).
Stack Canary (SSP)         PASS    CWE-121  Stack canary symbols detected (__stack_chk_fail).
RELRO                      PASS    CWE-123  Full RELRO enabled. GOT marked read-only.
FORTIFY_SOURCE             PASS    CWE-120  Discovered 4 fortified functions (_chk).
RPATH / RUNPATH            PASS    CWE-426  No insecure or rogue library search paths.
Stripped Symbols           INFO    CWE-200  Local symbol table (.symtab) retained.

Hardening Score: 100% | Production Status: PASSED
```

---

## Future Roadmap & Follow-Up Plans

### Step 4: Systemd Service Sandboxing & Least Privilege (CWE-250 / CWE-269)
* **Objective:** Enforce kernel and systemd-level isolation around the user-space kiosk binary to limit the blast radius of any application-level zero-day.
* **Planned Mitigations:**
  * **Filesystem & Mount Hardening:** `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, and `ReadOnlyPaths=/`.
  * **Privilege De-escalation:** `NoNewPrivileges=yes`, dropping capability sets via `CapabilityBoundingSet=`, and non-root execution.
  * **System Call Filtering (seccomp):** `SystemCallFilter=@system-service` to restrict kernel attack surfaces.

### Step 5: Runtime Integrity & Read-Only Root Filesystem (CWE-353 / CWE-284)
* **Objective:** Provide tamper resistance against direct physical flash access (eMMC / SD card removal) and prevent persistent operating system poisoning.
* **Planned Mitigations:**
  * **dm-verity / Read-Only Rootfs:** Block-level cryptographic verification of system partitions using dm-verity or read-only `overlayfs`.
  * **Hardware Root of Trust:** Measured boot chain binding bootloader stages to hardware cryptographic fuses / TPM.

