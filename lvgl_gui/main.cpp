#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <unistd.h>

#include "lvgl/lvgl.h"
#include "lvgl/src/drivers/display/drm/lv_linux_drm.h"
#include "lvgl/src/drivers/libinput/lv_libinput.h"

namespace {
    std::atomic<bool> g_running { true };
    void handleSignal(int /*sig*/) { g_running = false; }

    uint32_t custom_tick_get(void) {
        static const auto start = std::chrono::steady_clock::now();
        const auto now = std::chrono::steady_clock::now();
        return static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count()
        );
    }

    lv_display_t *initNative(const std::string &drmDevice,
                             const std::string &touchDevice,
                             lv_display_rotation_t rotation) {
        std::cout << "Initializing Linux DRM/KMS (" << drmDevice << ")...\n";
        lv_display_t *disp = lv_linux_drm_create();
        if (disp == nullptr) {
            std::cerr << "Error: Failed to create DRM display!\n";
            return nullptr;
        }

        if (lv_linux_drm_set_file(disp, drmDevice.c_str(), -1) != LV_RESULT_OK) {
            std::cerr << "Error: Failed to set DRM file!\n";
            return nullptr;
        }

        lv_display_set_rotation(disp, rotation);

        std::cout << "Initializing libinput (" << touchDevice << ")...\n";
        lv_indev_t *indev = lv_libinput_create(LV_INDEV_TYPE_POINTER, touchDevice.c_str());
        if (indev == nullptr) {
            std::cerr << "Warning: Failed to initialize libinput!\n";
        } else {
            lv_indev_set_display(indev, disp);
        }

        std::cout << "HAL initialization complete.\n";
        return disp;
    }
}

static constexpr lv_display_rotation_t DISPLAY_ROTATION = LV_DISPLAY_ROTATION_270;

int main()
{
    lv_init();
    lv_tick_set_cb(custom_tick_get);

    // --- HAL: display + input ---
    std::string drmDevice = "/dev/dri/card0";
    std::string touchDevice = "/dev/input/touchscreen";
    lv_display_t* disp = initNative(drmDevice, touchDevice, DISPLAY_ROTATION);

    if (disp == nullptr) {
        std::cerr << "HAL initialization failed. Exiting.\n";
        return 1;
    }

    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    // --- Sample UI ---
    lv_obj_t* label = lv_label_create(lv_screen_active());
    lv_label_set_text(label, "Airgap Update Demo\nWaiting for USB...");
    lv_obj_center(label);

    std::cout << "Application initialized, entering main event loop\n";

    // --- Main Event Loop ---
    while (g_running)
    {
        uint32_t sleepMs = lv_timer_handler();
        if (lv_display_get_default() == nullptr) {
            break;
        }

        if (sleepMs < 1) {
            sleepMs = 1;
        } else if (sleepMs > 30) {
            sleepMs = 30;
        }
        usleep(sleepMs * 1000);
    }

    std::cout << "Cleaning up and exiting...\n";
    lv_deinit();
    return 0;
}
