#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <print>
#include <filesystem> // For cleanup
#include <termios.h>  // For secure password input
#include <unistd.h>

#include "../common/crypto.hpp"
#include "../common/db.hpp"
#include "router.hpp"

// Secure Password Input (Unix)
std::string get_password(const std::string& prompt) {
    std::print("{}", prompt);
    std::cout.flush();

    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO; // Turn off echo
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::string pass;
    std::getline(std::cin, pass);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // Restore
    std::println(""); // Newline
    return pass;
}

std::string to_hex(const std::vector<uint8_t>& data) {
    std::string s; for(auto b : data) s += std::format("{:02x}", b); return s;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::println("Usage: ./nestd <HIVE_IP>");
        return 1;
    }
    std::string server_ip = argv[1];

    std::string db_path = "nest.db";
    nest::Database db;

    // 1. SECURE LOGIN / SETUP
    bool new_reg = !std::filesystem::exists(db_path);
    std::string pass = get_password("Enter Database Password: ");

    if (!db.open(db_path, pass)) {
        std::println(stderr, "Fatal: DB Open Failed (Wrong password?).");
        return 1;
    }

    nest::crypto::KeyPair my_keys, my_enc_keys;
    std::string my_name;

    if (db.has_identity()) {
        auto id = db.load_identity();
        if (!id) {
             std::println(stderr, "Fatal: Decryption failed."); return 1;
        }
        my_keys = id->keys; my_enc_keys = id->enc_keys; my_name = id->name;
        std::println("Welcome back, @{}", my_name);
    } else {
        // --- NEW REGISTRATION ---
        std::print("No identity found. Enter username to register: @");
        std::cin >> my_name;
        if (my_name.starts_with("@")) my_name.erase(0, 1);

        auto k1 = nest::crypto::generate_identity_key();
        auto k2 = nest::crypto::generate_ephemeral_key();
        my_keys = *k1; my_enc_keys = *k2;

        db.save_identity(my_keys, my_enc_keys, my_name);
        // Note: is_new_registration logic handled below via connection check
    }

    // 2. CONNECT & ROUTER SETUP
    nest::Router router(my_keys, my_enc_keys, db);

    // --- MESSAGE HANDLER WITH NAME RESOLUTION ---
    auto on_message = [&](const std::string& sender_hex, const venom::Payload& p) {
        // A. Check local cache
        std::string display_name = db.get_contact_name(sender_hex);

        // B. If unknown, ask Server (Lookups are fast)
        if (display_name.empty()) {
            auto remote = router.lookup_user_by_id(sender_hex); // Add this to Router!
            if (remote) {
                display_name = remote->username;
                db.set_contact_name(sender_hex, display_name); // Cache it
            } else {
                display_name = "Unknown[" + sender_hex.substr(0, 6) + "]";
            }
        }

        std::println("\n>>> @{}: {}", display_name, p.body());

        // C. Save to Local History
        db.save_message(sender_hex, p.body(), false);

        std::print("> "); std::cout.flush();
    };

    router.start(server_ip, 5555, on_message);

    // 3. REGISTRATION CONFIRMATION (With Rollback)
    if (new_reg) {
        std::println("Registering @{} with Hive...", my_name);
        if (!router.register_on_server(my_name)) {
            std::println(stderr, "Registration Failed! Username taken or server offline.");

            // CLEANUP: Close DB and delete file
            router.stop();
            db.close();
            std::filesystem::remove(db_path);

            std::println("Local DB deleted. Please try again.");
            return 1;
        }
        std::println("Registration Successful!");
    }

    // 4. MAIN LOOP
    std::string line;
    if (new_reg) std::getline(std::cin, line); // Consume newline

    while (true) {
        std::print("> "); std::cout.flush();
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;
        if (line == "/quit") break;

        if (line.starts_with("/send ")) {
            std::stringstream ss(line);
            std::string cmd, target, msg;
            ss >> cmd >> target;
            std::getline(ss, msg);
            if (!msg.empty() && msg[0] == ' ') msg.erase(0, 1);
            if (target.starts_with("@")) target.erase(0, 1);

            auto user = router.lookup_user(target);
            if (user) {
                if (router.send_text(*user, msg)) {
                    std::println("Sent.");
                    // Save to local history
                    db.save_message(to_hex(user->id_key), msg, true);
                } else std::println("Failed.");
            } else std::println("User not found.");
        }
    }
    return 0;
}