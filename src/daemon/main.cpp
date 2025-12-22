#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <print>   // C++23
#include <format>  // C++23
#include <sstream>

// Include our modules
#include "../common/crypto.hpp"
#include "../common/db.hpp"
#include "beacon.hpp"
#include "router.hpp"

// --- Helpers ---

// Convert Raw Bytes -> Hex String
std::string to_hex(const std::vector<uint8_t>& data) {
    std::string s;
    for(auto b : data) s += std::format("{:02x}", b);
    return s;
}

// Convert Raw Bytes -> Hex String (Overload for std::string container)
std::string to_hex(const std::string& data) {
    std::string s;
    for(auto b : data) s += std::format("{:02x}", static_cast<unsigned char>(b));
    return s;
}

// --- Main ---

int main() {
    std::println("=========================================");
    std::println("      NEST SECURE MESSENGER (DAEMON)     ");
    std::println("=========================================");

    // 1. Initialize Database
    // ----------------------
    nest::Database db;
    // In a real app, you'd get this from stdin or the GUI
    std::string db_pass = "secure_password_123";

    if (!db.open("nest.db", db_pass)) {
        std::println(stderr, "FATAL: Failed to open database.");
        return 1;
    }

    // 2. Identity Management
    // ----------------------
    nest::crypto::KeyPair my_keys;     // Ed25519
    nest::crypto::KeyPair my_enc_keys; // X25519
    std::string my_name;

    if (db.has_identity()) {
        auto id = db.load_identity();
        if (!id) { /* handle error */ }
        my_keys = id->keys;
        my_enc_keys = id->enc_keys; // Load X25519
        my_name = id->name;
    } else {
        std::println("[Main] First run. Generating 25519 Keys...");
        auto res_id = nest::crypto::generate_identity_key();   // Ed25519
        auto res_enc = nest::crypto::generate_ephemeral_key(); // X25519 (Reusing this function is fine, it generates X25519)
        if (!res_id || !res_enc) return 1;

        my_keys = *res_id;
        my_enc_keys = *res_enc;
        // Generate a random name for testing
        std::srand(std::time(nullptr));
        my_name = "User_" + std::to_string(std::rand() % 9000 + 1000);

        if (!db.save_identity(my_keys, my_enc_keys, my_name)) {
            std::println(stderr, "FATAL: Could not save identity.");
            return 1;
        }
    }

    std::println("Logged in as: {}", my_name);
    std::println("Fingerprint:  {}", to_hex(my_keys.public_key).substr(0, 16));
    std::println("Internal IP:  (Handled by VPN)");

    // 3. Start Networking Services
    // ----------------------------
    uint32_t port = 5555;

    // A. Beacon (Discovery)
    nest::BeaconService beacon(port, my_name, my_keys, my_enc_keys);
    beacon.start();

    // B. Router (Messaging)
    nest::Router router(port, my_keys, my_enc_keys, db);

    // Callback: What happens when we receive a message?
    router.start([&](const std::string& sender_pk_raw, const venom::Payload& p) {
        // sender_pk_raw comes in as raw bytes from the envelope
        // Note: In Router.cpp we fixed it to pass raw string, but let's double check.
        // Actually, looking at Router.cpp, it passes sender_hex_str in the callback?
        // Let's assume it passes HEX based on my previous snippet logic:
        // "on_message_(sender_hex_str, payload);"

        std::string sender_display = sender_pk_raw.substr(0, 8); // Short hash

        // Check if we know this person (simple lookup in peers for now)
        // In real app, we query DB contacts.

        std::println("");
        std::println(">>> [Encrypted Msg from {}]: {}", sender_display, p.body());
        std::print("> "); // Restore prompt
        std::cout.flush();
    });

    std::println("[Main] Services started. Waiting for peers...");
    std::println("[Help] Commands: /list, /send <index> <message>, /quit");

    // 4. Interactive Command Loop
    // ---------------------------
    std::string line;
    while (true) {
        std::print("> ");
        std::cout.flush();

        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        if (line == "/quit" || line == "/exit") {
            break;
        }
        else if (line == "/list") {
            auto peers = beacon.get_peers();
            if (peers.empty()) {
                std::println("No peers discovered yet.");
            } else {
                std::println("--- Discovered Peers ---");
                for (size_t i = 0; i < peers.size(); ++i) {
                    // peers[i].public_key is raw bytes string
                    std::string hex_key = to_hex(peers[i].public_key);
                    std::println("[{}] {} | IP: {} | Key: {}...",
                        i, peers[i].name, peers[i].ip, hex_key.substr(0, 8));
                }
            }
        }
        else if (line.starts_with("/send ")) {
            // Parse: /send 0 Hello World
            std::stringstream ss(line);
            std::string cmd;
            size_t index;
            std::string msg;

            ss >> cmd >> index; // Read command and index
            std::getline(ss, msg); // Read rest of line

            // Trim leading space from msg
            if (!msg.empty() && msg[0] == ' ') msg.erase(0, 1);

            auto peers = beacon.get_peers();
            if (index >= peers.size()) {
                std::println("Error: Invalid peer index. Use /list.");
                continue;
            }

            const auto& target = peers[index];
            std::string target_enc_hex = to_hex(target.enc_public_key); // Use the X25519 key

            std::println("Sending to {} ({}) ...", target.name, target.ip);

            bool sent = router.send_text(target.ip, target.port, target_enc_hex, msg);
            if (sent) {
                std::println("Message Sent.");
            } else {
                std::println("Error: Failed to send (Encryption or Network error).");
            }
        }
        else {
            std::println("Unknown command.");
        }
    }

    std::println("Shutting down...");
    router.stop();
    beacon.stop();
    db.close();
    return 0;
}