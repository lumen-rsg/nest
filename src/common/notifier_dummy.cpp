//
// Created by cv2 on 23.12.2025.
//

#if !defined(__linux__) && !defined(__APPLE__)

#include "notifier.hpp"
#include <iostream>

namespace nest {
    Notifier::Notifier(const std::string& app_name) {}
    Notifier::~Notifier() {}
    bool Notifier::notify(const std::string&, const std::string&) { return false; }
}

#endif