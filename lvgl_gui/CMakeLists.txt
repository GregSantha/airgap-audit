cmake_minimum_required(VERSION 3.25)

project(lvgl_gui C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Dependencies
find_package(PkgConfig REQUIRED)

pkg_check_modules(DRM REQUIRED libdrm)
pkg_check_modules(INPUT REQUIRED libinput)

# Set path to lv_conf.h
set(LV_BUILD_CONF_PATH "${CMAKE_CURRENT_SOURCE_DIR}/lv_conf.h" CACHE PATH "Path to lv_conf.h" FORCE)

# Disable LVGL examples, demos, and internal ThorVG to speed up the build
set(CONFIG_LV_BUILD_EXAMPLES OFF CACHE BOOL "")
set(CONFIG_LV_BUILD_DEMOS OFF CACHE BOOL "")
set(CONFIG_LV_USE_THORVG_INTERNAL OFF CACHE BOOL "")

set(ENABLE_SECURITY_HARDENING ON CACHE BOOL "")

add_subdirectory(external/lvgl)

# Ensure LVGL itself can find the DRM and libinput headers
target_include_directories(lvgl PUBLIC ${DRM_INCLUDE_DIRS} ${INPUT_INCLUDE_DIRS})

add_executable(lvgl_gui main.cpp)
target_include_directories(lvgl_gui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    external
)

target_link_libraries(lvgl_gui PRIVATE lvgl ${DRM_LIBRARIES} ${INPUT_LIBRARIES})
target_include_directories(lvgl_gui PRIVATE
    ${DRM_INCLUDE_DIRS}
    ${INPUT_INCLUDE_DIRS}
)

target_compile_options(lvgl_gui PRIVATE
    -Wall -Wextra -Wpedantic
)

if(ENABLE_SECURITY_HARDENING)
    target_compile_options(lvgl_gui PRIVATE
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=3
        -fPIE
    )

    target_link_options(lvgl_gui PRIVATE
        -Wl,-z,relro,-z,now
        -Wl,-z,noexecstack
        -pie
    )
endif()
