# LVGL GUI Application & Build Environment

Workspace for the C++ source code, CMake build configuration, and ARMv8 cross-compilation environment for the `lvgl_gui` application.

## Suggested Structure
```
lvgl_gui/
├── CMakeLists.txt        # CMake build configuration
├── toolchain-armv8.cmake # Cross-compilation toolchain file (if applicable)
├── src/                  # C++ application source code
└── bin/                  # Target output directory
    └── lvgl_gui          # Compiled AArch64 binary running on DietPi
```
