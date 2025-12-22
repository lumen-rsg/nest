#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <print>
#include <format>
#include <sstream>

#include "../common/crypto.hpp"
#include "../common/db.hpp"
#include "router.hpp"

std::string to_hex(const std::vector<uint8_t>& data) {
    std::string s;
    for(auto b : data) s += std::format("{:02x}", b);
    return s;
}

int main(int argc, char* argv[]) {
    std::println("=========================================");
    std::println("       NEST SECURE CLIENT (DAEMON)       ");
    std::println("=========================================");

    if (argc < 2) {
        std::println("Usage: ./nestd <HIVE_IP>");
        std::println("Example: ./nestd 127.0.0.1");
        return 1;
    }
    std::string server_ip = argv[1];
    uint16_t server_port = 5555;

    // 1. Database
    nest::Database db;
    // In production, ask user for password via stdin
    if (!db.open("nest.db", "pass")) {
        std::println(stderr, "Fatal: Could not open database.");
        return 1;
    }

    nest::crypto::KeyPair my_keys, my_enc_keys;
    std::string my_name;
    bool is_new_registration = false;

    // 2. Identity Check
    if (db.has_identity()) {
        auto id = db.load_identity();
        if (!id) {
            std::println(stderr, "Fatal: Failed to load identity (wrong password?).");
            return 1;
        }
        my_keys = id->keys;
        my_enc_keys = id->enc_keys;
        my_name = id->name;
        std::println("Welcome back, @{}", my_name);
    }
    else {
        std::println(">>> REGISTRATION <<<");
        std::print("Enter your desired username: @");
        std::string input_name;
        std::cin >> input_name;

        // Strip @ if typed
        if (input_name.starts_with("@")) input_name.erase(0, 1);

        std::println("Generating Crypto Keys...");
        auto k1 = nest::crypto::generate_identity_key();
        auto k2 = nest::crypto::generate_ephemeral_key();
        if (!k1 || !k2) return 1;

        my_keys = *k1;
        my_enc_keys = *k2;
        my_name = input_name;
        is_new_registration = true;

        // Save locally first
        db.save_identity(my_keys, my_enc_keys, my_name);
    }

    // 3. Start Router
    nest::Router router(my_keys, my_enc_keys, db);

    // Start Polling Loop
    router.start(server_ip, server_port, [](const std::string& sender_hex, const venom::Payload& p) {
        // We receive the raw sender hex ID.
        // In a full app, we would Lookup this ID to show the username.
        std::println("\n>>> MSG from [{}..]: {}", sender_hex.substr(0, 8), p.body());
        std::print("> "); std::cout.flush();
    });

    // 4. Register / Sync with Server
    // Even if we have local keys, we register to ensure Hive knows we exist/updates keys
    std::println("Connecting to Hive at {}...", server_ip);

    if (router.register_on_server(my_name)) {
        std::println("Registration/Login Confirmed for @{}", my_name);
    } else {
        std::println(stderr, "Failed to register with Hive! (Username taken or Server offline?)");
        if (is_new_registration) {
            // In a real app, maybe delete local DB so user can try again
            return 1;
        }
    }

    std::println("Ready. Commands: /send @user <msg>, /quit");

    // 5. Command Loop
    std::string line;
    // Consume leftover newline from cin if we did registration
    if (is_new_registration) std::getline(std::cin, line);

    while (true) {
        std::print("> "); std::cout.flush();
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;
        if (line == "/quit") break;

        if (line.starts_with("/send ")) {
            // Format: /send @username hello world
            std::stringstream ss(line);
            std::string cmd, target, msg;
            ss >> cmd >> target;
            std::getline(ss, msg);

            // Trim msg
            if (!msg.empty() && msg[0] == ' ') msg.erase(0, 1);

            if (target.empty() || msg.empty()) {
                std::println("Usage: /send @username message");
                continue;
            }

            if (target.starts_with("@")) target.erase(0, 1);

            std::println("Looking up @{}...", target);
            auto remote_user = router.lookup_user(target);

            if (remote_user) {
                std::println("Found (ID: {}...). Sending...", to_hex(remote_user->id_key).substr(0, 8));
                if (router.send_text(*remote_user, msg)) {
                    std::println("Sent.");
                } else {
                    std::println("Send Failed.");
                }
            } else {
                std::println("Error: User @{} not found on this Hive.", target);
            }
        }
    }

    return 0;
}