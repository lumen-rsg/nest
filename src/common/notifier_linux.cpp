//
// Created by cv2 on 23.12.2025.
//

#ifdef __linux__

#include "notifier.hpp"
#include <libnotify/notify.h>
#include <iostream>
#include <print>

namespace nest {

    Notifier::Notifier(const std::string& app_name) : app_name_(app_name) {
        if (!notify_init(app_name_.c_str())) {
            std::println(stderr, "[Notifier] Failed to init libnotify.");
            initialized_ = false;
        } else {
            initialized_ = true;
        }
    }

    Notifier::~Notifier() {
        if (initialized_) {
            notify_uninit();
        }
    }

    bool Notifier::notify(const std::string& title, const std::string& body) {
        if (!initialized_) return false;

        NotifyNotification* n = notify_notification_new(title.c_str(), body.c_str(), nullptr);
        if (!n) return false;

        // Set timeout to 3000ms (3 seconds)
        notify_notification_set_timeout(n, 3000);

        GError* error = nullptr;
        if (!notify_notification_show(n, &error)) {
            std::println(stderr, "[Notifier] Error: {}", error->message);
            g_error_free(error);
            g_object_unref(G_OBJECT(n));
            return false;
        }

        g_object_unref(G_OBJECT(n));
        return true;
    }

} // namespace nest

#endif // __linux__