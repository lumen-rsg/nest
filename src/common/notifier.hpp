//
// Created by cv2 on 23.12.2025.
//

#pragma once
#include <string>

namespace nest {

    class Notifier {
    public:
        Notifier(const std::string& app_name);
        ~Notifier();

        // Send a desktop notification
        // Returns true if dispatched successfully
        bool notify(const std::string& title, const std::string& body);

    private:
        std::string app_name_;
        bool initialized_ = false;
    };

} // namespace nest