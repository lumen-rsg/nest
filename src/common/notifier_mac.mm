//
// Created by cv2 on 23.12.2025.
//

#ifdef __APPLE__

#include "notifier.hpp"
#import <Foundation/Foundation.h>

namespace nest {

Notifier::Notifier(const std::string& app_name) : app_name_(app_name) {
    // macOS notifications don't need explicit init for CLI tools
    initialized_ = true;
}

Notifier::~Notifier() {
    // Nothing to teardown
}

bool Notifier::notify(const std::string& title, const std::string& body) {
    @autoreleasepool {
        NSUserNotification *notification = [[NSUserNotification alloc] init];

        // Convert std::string to NSString
        NSString *nsTitle = [NSString stringWithUTF8String:title.c_str()];
        NSString *nsBody = [NSString stringWithUTF8String:body.c_str()];

        [notification setTitle:nsTitle];
        [notification setInformativeText:nsBody];
        [notification setSoundName:NSUserNotificationDefaultSoundName];

        [[NSUserNotificationCenter defaultUserNotificationCenter] deliverNotification:notification];
    }
    return true;
}

} // namespace nest

#endif // __APPLE__