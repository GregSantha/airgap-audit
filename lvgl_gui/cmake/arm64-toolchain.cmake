# CMake Toolchain file for ARM64 (aarch64-linux-gnu)
# This is used for cross-compiling the LVGL application

if(NOT CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "aarch64")
  message(STATUS "Cross-compiling for ARM64")
  set(CMAKE_SYSTEM_NAME Linux)
  set(CMAKE_SYSTEM_PROCESSOR aarch64)

  # Specify the cross compiler
  set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
  set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)

  # Where is the target environment located?
  # For Ubuntu multiarch, we want pkg-config to look in the arm64 directories
  set(ENV{PKG_CONFIG_LIBDIR} "/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/share/pkgconfig")
  set(ENV{PKG_CONFIG_SYSROOT_DIR} "/")

  set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
else()
  message(STATUS "Native ARM64 build detected, bypassing cross-compilation toolchain settings")
endif()

# Target CPU optimizations (Cortex-A53 target)
add_compile_options(-mcpu=cortex-a53)
