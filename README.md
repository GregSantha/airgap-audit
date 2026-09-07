# airgap-audit

> **Offline USB Update Engine & Binary Security Auditor for Embedded Linux Applications (ARMv8)**

Built for air-gapped embedded systems (e.g. DietPi on ARMv8) where the application is closed in a box, has no network access, and is updated via a physical USB pendrive upon boot.


> 📖 **Security Walkthrough & Guide:** See [docs/evolution.md](docs/evolution.md) for the step-by-step breakdown of vulnerabilities (CWEs), fixes, and hardware proofs.

---

## Development Setup with `uv`

This project uses [`uv`](https://github.com/astral-sh/uv) for dependency resolution, virtual environments, packaging, and tool execution.

### 1. Install Dependencies
```bash
uv sync --extra dev
```

### 2. Run Tests
```bash
uv run pytest -v
```

### 3. Static Type Checking & Linting
```bash
uv run mypy src/
uv run ruff check src/ tests/
```

### 4. Run the CLI
```bash
# Print help
uv run airgap-audit --help

# Audit an ELF binary for exploit mitigations (NX, PIE, Canary, Full RELRO, Fortify, RPATH)
uv run airgap-audit audit elf lvgl_gui/build/arm64-release/lvgl_gui
uv run airgap-audit audit elf lvgl_gui/build/arm64-release/lvgl_gui --format json
uv run airgap-audit audit elf lvgl_gui/build/arm64-release/lvgl_gui --strict --min-score 85

# Create a sealed .update container with pre-flight binary mitigation audit
uv run airgap-audit package create --payload lvgl_gui --key keys/private_key.pem --out lvgl_gui.update --audit

# Inspect container metadata
uv run airgap-audit package inspect --package lvgl_gui.update

# Run companion update check (on target device)
uv run airgap-audit update-check
```

### 5. Build Distribution Wheel
```bash
uv build
```
This produces both a source distribution (`.tar.gz`) and a standalone wheel (`.whl`) in `dist/`:
- `dist/airgap_audit-0.3.0-py3-none-any.whl`

---

## Target Deployment (DietPi / Embedded)

To deploy the companion updater package onto the target device:

```bash
# 1. Transfer the wheel to the board:
scp dist/airgap_audit-0.3.0-py3-none-any.whl dietpi@<dietpi_ip>:/tmp/

# 2. Install on DietPi:
sudo pip install --break-system-packages /tmp/airgap_audit-0.3.0-py3-none-any.whl
```

---

## Repository Structure
```
airgap-audit/
├── pyproject.toml              # Build configuration and project dependencies
├── uv.lock                     # Pinned dependency lockfile
├── src/
│   └── airgap_audit/
│       ├── cli.py              # CLI entry point (airgap-audit)
│       └── companion/
│           └── updater.py      # Companion update agent (ExecStartPre / airgap-updater)
├── lvgl_gui/                   # C++ application workspace & build environment
└── tests/
    ├── test_smoke.py           # Verification tests
    └── test_updater.py         # Hardware & partition logic tests (using real lsblk dumps)
```
