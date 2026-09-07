# airgap-audit

> **Hardened Offline Update Engine & ELF Binary Exploit Mitigation Auditor for Embedded Linux (ARMv8 / AArch64)**

Designed for offline, air-gapped embedded systems (e.g. DietPi on ARMv8) where devices are isolated in physical enclosures without network access, and must be reliably and securely updated via physical USB media at boot.

**Detailed Security Architecture & Vulnerability Evolution:** See [docs/evolution.md](docs/evolution.md) for the comprehensive breakdown of addressed CWEs, threat models, and real hardware verification proofs.

---

## The Problem

Air-gapped embedded systems cannot utilize cloud-based OTA agents. However, physical USB updates present severe attack vectors if implemented naively:

1. **Unauthenticated Firmware Execution ([CWE-494](https://cwe.mitre.org/data/definitions/494.html) / [CWE-353](https://cwe.mitre.org/data/definitions/353.html)):** Anyone with physical access can plug in a pendrive with a rogue executable or backdoor shell script. If the updater executes as root, the host is compromised.
2. **Downgrade / Rollback Attacks ([CWE-1328](https://cwe.mitre.org/data/definitions/1328.html)):** Attackers can force the system to reinstall older, authentically signed binaries that contain known vulnerabilities.
3. **Exploitation of Vulnerable Binaries ([CWE-119](https://cwe.mitre.org/data/definitions/119.html), [CWE-121](https://cwe.mitre.org/data/definitions/121.html), [CWE-123](https://cwe.mitre.org/data/definitions/123.html), [CWE-426](https://cwe.mitre.org/data/definitions/426.html)):** Even authentic binaries with memory corruption bugs can be exploited if compiled without standard defense-in-depth mitigations (NX, PIE, Stack Canaries, Full RELRO, FORTIFY_SOURCE=3, clean RPATHs).

---

## End-to-End Architecture

```
[ DEVELOPER / CI WORKFLOW ]
 1. Cross-compile hardened ARM64 ELF (CMake + GCC/Clang with security flags)
 2. Pre-flight ELF Mitigation Audit (airgap-audit audit elf --strict)
 3. Ed25519 Sign & Pack into 140-byte sealed container (airgap-audit package create --audit)
    │
    ▼
[ PHYSICAL USB MEDIA ]
 FAT32 / ext4 USB drive containing root file: lvgl_gui.update
    │
    ▼
[ EMBEDDED TARGET (DietPi ARMv8) ]
 Systemd boots: lvgl_gui.service
 ├── ExecStartPre: airgap-updater
 │   ├── lsblk JSON filter: Identify removable USB drives
 │   ├── Transient read-only mount
 │   ├── Cryptographic verification: Validate Ed25519 signature against /etc/airgap/public_key.pem
 │   ├── Anti-rollback validation: Verify Security Epoch >= installed & App Version > installed
 │   ├── Atomic installation: .new staging -> .bak backup -> atomic os.replace()
 │   └── Update persistent state: /etc/airgap/installed_version & security_epoch
 └── ExecStart: Launch hardened C++ LVGL DRM/KMS GUI application as non-root user
```

---

## Security Mitigation & Defense Matrix

| Category | Mitigation | CWE | Defense Mechanism | Where Enforced |
| :--- | :--- | :--- | :--- | :--- |
| **Authenticity** | Asymmetric Signatures | **CWE-494** | Ed25519 digital signature over 76-byte container header | Packaging CLI & Companion Updater |
| **Integrity** | Cryptographic Digest | **CWE-353** | SHA-256 payload verification before and after staging | Sealed `.update` Container |
| **Anti-Rollback**| Monotonic Epochs | **CWE-1328**| Strict rejection of packages with `epoch < current_epoch` | Companion Updater State Engine |
| **Stack Defense**| No-Execute Stack (NX) | **CWE-119** | `PT_GNU_STACK` verified Non-Executable (`RW`, not `RWE`) | `ElfAuditor` & CMake `-Wl,-z,noexecstack` |
| **ASLR** | Position Independent | **CWE-119** | `ET_DYN` + `DT_DEBUG` verified for address randomization | `ElfAuditor` & CMake `-fPIE -pie` |
| **Buffer Overflow**| Stack Canaries (SSP) | **CWE-121** | `__stack_chk_fail` symbol verified in binary symbol tables | `ElfAuditor` & CMake `-fstack-protector-strong` |
| **GOT Overwrite** | Full RELRO | **CWE-123** | `PT_GNU_RELRO` + `DT_BIND_NOW` / `DF_1_NOW` (read-only GOT)| `ElfAuditor` & CMake `-Wl,-z,relro,-z,now` |
| **Format String**| Fortified Libc Calls | **CWE-120** | Bounds-checked standard library calls (`*_chk`) discovered| `ElfAuditor` & CMake `-D_FORTIFY_SOURCE=3` |
| **Lib Hijacking**| RPATH Sanitization | **CWE-426** | Disallow insecure relative (`./`) or writable library search paths | `ElfAuditor` dynamic tag inspector |

---

## Development Setup with `uv`

This repository uses [`uv`](https://github.com/astral-sh/uv) for fast, reproducible Python dependency resolution and tooling.

### 1. Install Dependencies
```bash
uv sync --extra dev
```

### 2. Run Test Suite
```bash
uv run pytest -v
```

### 3. Static Type Checking & Linting
```bash
uv run mypy src/ tests/
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
```

---

## CLI Usage Guide (`airgap-audit`)

### 1. Generate Signing Keypair
```bash
# Generates private_key.pem (0600) and public_key.pem
uv run airgap-audit keygen --out-dir ./keys
```

### 2. Audit an ELF Binary for Exploit Mitigations
```bash
# Human-readable colored mitigation table
uv run airgap-audit audit elf lvgl_gui/build/arm64-release/lvgl_gui

# Machine-readable JSON output for CI/CD pipelines
uv run airgap-audit audit elf lvgl_gui/build/arm64-release/lvgl_gui --format json

# Strict gating: Exits with non-zero code if any check fails or score < 85%
uv run airgap-audit audit elf lvgl_gui/build/arm64-release/lvgl_gui --strict --min-score 85
```

### 3. Build Sealed Update Container
```bash
# Auto-detects Version, Security Epoch, and Device ID from lvgl_gui/version.h
# Runs pre-flight mitigation audit before sealing container
uv run airgap-audit package create \
  --payload lvgl_gui/build/arm64-release/lvgl_gui \
  --key keys/private_key.pem \
  --out lvgl_gui.update \
  --audit
```

### 4. Inspect Container Metadata
```bash
uv run airgap-audit package inspect --package lvgl_gui.update
```

### 5. Build Distribution Packages (Wheel & Sdist)
```bash
uv build
```
Produces `dist/airgap_audit-0.3.0-py3-none-any.whl` and `dist/airgap_audit-0.3.0.tar.gz`.

---

## Embedded Target Deployment (DietPi / ARMv8)

### 1. Provision Public Key on Target
```bash
sudo mkdir -p /etc/airgap
sudo cp keys/public_key.pem /etc/airgap/public_key.pem
sudo chmod 644 /etc/airgap/public_key.pem
```

### 2. Install Companion Updater
```bash
# Transfer and install wheel system-wide on target
sudo pip install --break-system-packages airgap_audit-0.3.0-py3-none-any.whl
```

### 3. Install Systemd Service Unit
```bash
sudo cp lvgl_gui/service/lvgl_gui.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lvgl_gui.service
```

### 4. Verified Hardware Boot Log (Real DietPi ARM64 Output)
```text
Sep 07 20:19:36 DietPi systemd[1]: Starting lvgl_gui.service - LVGL GUI Application with Offline USB Updater...
Sep 07 20:19:38 DietPi python3[452]: [20:19:38] [INFO] [updater] === AirGap Offline USB Companion Updater Check ===
Sep 07 20:19:38 DietPi python3[452]: [20:19:38] [INFO] [updater] Target: /home/dietpi/lvgl_gui (installed version: 0, epoch: 0)
Sep 07 20:19:38 DietPi python3[452]: [20:19:38] [INFO] [updater] Public key: /etc/airgap/public_key.pem (exists=True)
Sep 07 20:19:38 DietPi python3[452]: [20:19:38] [INFO] [updater] Detected removable USB partition: /dev/sda1 (fs=vfat, mount=None)
Sep 07 20:19:38 DietPi python3[452]: [20:19:38] [INFO] [updater] Checking /dev/sda1 for 'lvgl_gui.update'...
Sep 07 20:19:38 DietPi python3[452]: [20:19:38] [INFO] [updater] Found update package: /tmp/airgap_usb/lvgl_gui.update (1209092 bytes). Verifying signature...
Sep 07 20:19:38 DietPi python3[452]: [20:19:38] [INFO] [updater] Verified update: App Version 200, Epoch 1 (current Epoch 0), device 'lvgl_gui', SHA-256 21b1ae6b91... Installing to /home/dietpi/lvgl_gui
Sep 07 20:19:38 DietPi python3[452]: [20:19:38] [INFO] [updater] Successfully updated /home/dietpi/lvgl_gui to App Version 200 (Security Epoch 1)
Sep 07 20:19:39 DietPi systemd[1]: Started lvgl_gui.service - LVGL GUI Application with Offline USB Updater.
```

---

## Repository Structure

```
airgap-audit/
├── src/airgap_audit/
│   ├── audit/                      # Binary exploit mitigation analyzer (pyelftools)
│   │   ├── auditor.py              # NX, PIE, Canary, RELRO, Fortify, RPATH auditor
│   │   └── models.py               # Pydantic mitigation models, scoring & severity
│   ├── core/                       # Cryptographic engine & sealed container format
│   │   ├── container.py            # 140-byte AGUP format parser & unpacker
│   │   ├── crypto.py               # Ed25519 signing, verification & streaming SHA-256
│   │   └── version.py              # version.h C++ header parser & SemVer converter
│   ├── companion/                  # Embedded device runtime agent
│   │   └── updater.py              # USB discovery, safe mounting & atomic state engine
│   └── cli.py                      # Typer CLI (keygen, package, audit, update-check)
├── lvgl_gui/                       # ARMv8 DRM/KMS C++ GUI application
│   ├── main.cpp                    # LVGL application with DRM display HAL
│   ├── version.h                   # Single source of truth (Version, Epoch, Device ID)
│   ├── CMakeLists.txt              # Build configuration with explicit hardening flags
│   ├── CMakePresets.json           # Native and ARM64 cross-compilation presets
│   └── service/
│       └── lvgl_gui.service        # Unbuffered systemd pre-boot updater service
├── docs/
│   └── evolution.md                # Progressive security breakdown (Steps 1-3 + Roadmap)
├── tests/                          # Automated Pytest suite (40 tests, 100% passing)
│   ├── test_audit.py               # ELF mitigation analysis scenarios & ARM64 bin tests
│   ├── test_container.py           # Container tamper resistance & rollback tests
│   ├── test_crypto.py              # Ed25519 cryptographic round-trip tests
│   ├── test_updater.py             # Hardware partition discovery (real DietPi lsblk)
│   └── test_smoke.py               # CLI integration smoke tests
├── .github/workflows/
│   └── ci.yml                      # CI/CD: lint, mypy, pytest, ARM64 build & release
└── pyproject.toml                  # Project packaging, dependencies & CLI entrypoints
```
