# airgap-audit

> **Offline USB Update Engine & Binary Security Auditor for Embedded Linux Applications (ARMv8)**

Built for air-gapped embedded systems (e.g. DietPi on ARMv8) where the application is closed in a box, has no network access, and is updated via a physical USB pendrive upon boot.

---

## Development Setup with `uv`

This project uses [`uv`](https://github.com/astral-sh/uv) for dependency resolution, virtual environments, and tool execution.

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

# Check version
uv run airgap-audit version

# Run companion update check
uv run airgap-audit update-check
```

---

## Repository Structure
```
airgap-audit/
├── pyproject.toml              # Build configuration and project dependencies
├── uv.lock                     # Pinned dependency lockfile
├── src/
│   └── airgap_audit/
│       ├── cli.py              # CLI entry point
│       └── companion/
│           └── updater.py      # Companion update agent (e.g. systemd ExecStartPre)
├── lvgl_gui/                   # C++ application workspace & build environment
└── tests/
    └── test_smoke.py           # Verification tests
```
