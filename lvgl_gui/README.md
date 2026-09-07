# LVGL GUI Application & Build Environment

Workspace for the C++ source code, CMake build configuration, and ARMv8 cross-compilation environment for the `lvgl_gui` application.

## ARM64 Cross-Compilation

To cross-compile the application for the ARM A53 target (ARM64 / DRM/KMS backend) from Ubuntu 24.04:

1. **Configure Multiarch Repositories**:
   Edit `/etc/apt/sources.list.d/ubuntu.sources` to add `Architectures: amd64`, then add the ARM64 ports repository:
   ```bash
   sudo bash -c 'cat <<EOF > /etc/apt/sources.list.d/arm64-ports.sources
   Types: deb
   URIs: http://ports.ubuntu.com/ubuntu-ports/
   Suites: noble noble-updates noble-backports
   Components: main restricted universe multiverse
   Architectures: arm64
   Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
   EOF'
   ```

2. **Install Build Tools, Cross-Compiler and Target Libraries**:
   ```bash
   sudo apt update
   sudo apt install build-essential cmake\
                    g++-aarch64-linux-gnu \
                    libdrm-dev:arm64 \
                    libinput-dev:arm64 \
                    libmodbus-dev:arm64
   ```

3. **Initialize Git Submodules**:
   ```bash
   git submodule update --init --recursive
   ```

4. **Build Target Binaries**:
   ```bash
   cmake --preset arm64-release
   cmake --build --preset arm64-release -j$(nproc)
   ```
   *(Produces `build/arm64-release/lvgl_gui`)*

---
