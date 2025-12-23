#ifdef __APPLE__

#include "notifier.hpp"
#include <string>
#include <vector>
#include <iostream>
#include <cstdlib>

namespace nest {

// Helper to escape characters for AppleScript (Double Quotes and Backslashes)
static std::string escape_for_applescript(const std::string& input) {
    std::string output;
    output.reserve(input.size());
    for (char c : input) {
        if (c == '"' || c == '\\') {
            output.push_back('\\');
        }
        output.push_back(c);
    }
    return output;
}

Notifier::Notifier(const std::string& app_name) : app_name_(app_name) {
    initialized_ = true;
}

Notifier::~Notifier() {}

bool Notifier::notify(const std::string& title, const std::string& body) {
    // Sanitize inputs to prevent command injection
    std::string safe_title = escape_for_applescript(title);
    std::string safe_body = escape_for_applescript(body);
    std::string safe_app = escape_for_applescript(app_name_);

    // Construct AppleScript command
    // display notification "message" with title "title" subtitle "subtitle"
    std::string command = "osascript -e 'display notification \"" + safe_body +
                          "\" with title \"" + safe_app +
                          "\" subtitle \"" + safe_title + "\"'";

    // Execute
    int ret = std::system(command.c_str());
    return (ret == 0);
}

} // namespace nest

#endif // __APPLE__