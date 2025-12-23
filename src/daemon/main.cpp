#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <print>
#include <format>
#include <sstream>
#include <filesystem>
#include <termios.h>
#include <unistd.h>

// Third-party
#include <nlohmann/json.hpp>

// Internal Modules
#include "../common/crypto.hpp"
#include "../common/db.hpp"
#include "../common/notifier.hpp"
#include "router.hpp"
#include "transfer_manager.hpp"
#include "ipc_server.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;

// --- Helper Functions ---

// Secure Password Input (Unix/macOS) - Disables terminal echo
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

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // Restore settings
    std::println(""); // Newline
    return pass;
}

std::string to_hex(const std::vector<uint8_t>& data) {
    std::string s;
    for(auto b : data) s += std::format("{:02x}", b);
    return s;
}

// --- Main Application ---

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

    std::string db_path = "nest.db";
    nest::Database db;

    // Check if this is a fresh installation for rollback logic
    bool is_new_registration = !fs::exists(db_path);

    // 1. Database Login / Setup
    std::string pass = get_password("Enter Database Password: ");

    if (!db.open(db_path, pass)) {
        std::println(stderr, "Fatal: Could not open database. Wrong password or corrupted file.");
        return 1;
    }

    nest::crypto::KeyPair my_keys;
    nest::crypto::KeyPair my_enc_keys;
    std::string my_name;

    // 2. Identity Loading or Generation
    if (db.has_identity()) {
        auto id = db.load_identity();
        if (!id) {
            std::println(stderr, "Fatal: Identity decryption failed.");
            return 1;
        }
        my_keys = id->keys;
        my_enc_keys = id->enc_keys;
        my_name = id->name;
        std::println("Welcome back, @{}", my_name);
    }
    else {
        // Registration Wizard
        std::println(">>> NEW USER REGISTRATION <<<");
        std::print("Enter your desired username: @");
        std::string input_name;
        std::cin >> input_name;

        // Strip @ if typed by user
        if (input_name.starts_with("@")) input_name.erase(0, 1);

        std::println("Generating Cryptographic Keys (Ed25519 + X25519)...");
        auto k1 = nest::crypto::generate_identity_key();
        auto k2 = nest::crypto::generate_ephemeral_key(); // Reusing ephemeral gen for X25519 static key

        if (!k1 || !k2) {
            std::println(stderr, "Fatal: Crypto generation failed.");
            return 1;
        }

        my_keys = *k1;
        my_enc_keys = *k2;
        my_name = input_name;
        is_new_registration = true;

        // Save to local DB immediately
        if (!db.save_identity(my_keys, my_enc_keys, my_name)) {
            std::println(stderr, "Fatal: Failed to save identity to DB.");
            return 1;
        }
        std::println("Local identity created.");
    }

    // 3. Initialize Core Components
    nest::Router router(my_keys, my_enc_keys, db);
    nest::TransferManager transfers(router);
    nest::Notifier notifier("Nest");
    nest::IPCServer ipc(router, transfers);

    // 4. Define Message Handler (Callback from Router)
    auto on_message = [&](const std::string& sender_hex, const venom::Payload& p) {
        // A. Resolve Sender Name
        std::string display_name = db.get_contact_name(sender_hex);

        // If not in cache, ask the server
        if (display_name.empty()) {
            auto remote = router.lookup_user_by_id(sender_hex);
            if (remote) {
                display_name = remote->username;
                db.set_contact_name(sender_hex, display_name); // Cache it
            } else {
                display_name = "Unknown[" + sender_hex.substr(0, 6) + "]";
            }
        }

        // B. Prepare IPC Event Payload (for GUI)
        json j_payload;
        j_payload["sender"] = display_name;
        j_payload["sender_key"] = sender_hex;
        j_payload["timestamp"] = p.timestamp();

        std::string notif_body;

        // C. Handle Payload Types
        if (p.type() == venom::Payload::TEXT) {
            j_payload["type"] = "text";
            j_payload["body"] = p.body();

            std::println("\n>>> @{}: {}", display_name, p.body());
            notif_body = p.body();
        }
        else if (p.type() == venom::Payload::MEDIA) {
            std::string filename = p.attachment().filename();

            j_payload["type"] = "media";
            j_payload["filename"] = filename;
            j_payload["filesize"] = p.attachment().size_bytes();
            j_payload["mimetype"] = p.attachment().mime_type();

            std::println("\n>>> @{} sent a FILE: {}", display_name, filename);
            std::println("    Size: {} bytes | MIME: {}", p.attachment().size_bytes(), p.attachment().mime_type());
            std::println("    [Auto-downloading to ./downloads/]");
            notif_body = "Sent a file: " + filename;

            // Auto-download logic
            fs::create_directories("downloads");
            transfers.queue_download(p.attachment(), "downloads", display_name);
        }
        else if (p.type() == venom::Payload::VOICE) {
            j_payload["type"] = "voice";
            j_payload["size"] = p.embedded_data().size();

            std::println("\n>>> @{} sent a VOICE message", display_name);
            notif_body = "Sent a voice message.";
        }

        // D. Broadcast to GUI via IPC
        ipc.broadcast_event("new_message", j_payload);

        // E. Desktop Notification
        notifier.notify("Message from @" + display_name, notif_body);

        // F. Save to History
        db.save_message(sender_hex, p.body(), false);

        // Restore CLI prompt
        std::print("> ");
        std::cout.flush();
    };

    // 5. Start All Services
    std::println("Connecting to Hive at {}...", server_ip);

    // Start polling the server
    router.start(server_ip, server_port, on_message);

    // Start background file worker
    transfers.start();

    // Start IPC server for GUI (tcp://127.0.0.1:9002)
    ipc.start();

    // 6. Server Registration / Sync
    // We register on every startup to ensure the server has our latest presence
    if (router.register_on_server(my_name)) {
        std::println("Connected and Registered as @{}", my_name);

        // Notify GUI we are ready
        json info;
        info["username"] = my_name;
        info["pubkey"] = to_hex(my_keys.public_key);
        ipc.broadcast_event("ready", info);

    } else {
        std::println(stderr, "Registration Failed! Username taken or Server unreachable.");

        // Critical Rollback: If this was a new user, delete the local DB so they can try again.
        if (is_new_registration) {
            ipc.stop();
            transfers.stop();
            router.stop();
            db.close();
            fs::remove(db_path);
            std::println("Local database deleted. Please restart to try a different username.");
            return 1;
        }
    }

    std::println("System Ready.");
    std::println("CLI Commands: /send @user <msg>, /upload <file> @user, /quit");
    std::println("(GUI Client can now connect on port 9002)");

    // 7. Command Loop
    std::string line;

    // Clear buffer if we used cin during registration wizard
    if (is_new_registration) std::getline(std::cin, line);

    while (true) {
        std::print("> ");
        std::cout.flush();

        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;
        if (line == "/quit" || line == "/exit") break;

        // Command: SEND TEXT
        if (line.starts_with("/send ")) {
            // Syntax: /send @user Hello World
            std::stringstream ss(line);
            std::string cmd, target_str, msg;
            ss >> cmd >> target_str;
            std::getline(ss, msg);

            // Trim leading space from message
            if (!msg.empty() && msg[0] == ' ') msg.erase(0, 1);

            if (target_str.empty() || msg.empty()) {
                std::println("Usage: /send @username <message>");
                continue;
            }

            // Remove '@' if present
            if (target_str.starts_with("@")) target_str.erase(0, 1);

            std::println("Resolving @{}...", target_str);
            auto remote = router.lookup_user(target_str);

            if (remote) {
                if (router.send_text(*remote, msg)) {
                    std::println("Sent.");
                    // Save to local history (self)
                    db.save_message(to_hex(remote->id_key), msg, true);
                } else {
                    std::println("Failed to send message (Server error or User not found).");
                }
            } else {
                std::println("Error: User @{} not found.", target_str);
            }
        }
        // Command: UPLOAD FILE
        else if (line.starts_with("/upload ")) {
            // Syntax: /upload <path> @user [caption]
            std::stringstream ss(line);
            std::string cmd, path, target_str, caption;

            ss >> cmd >> path >> target_str;
            std::getline(ss, caption); // Optional caption

            if (path.empty() || target_str.empty()) {
                std::println("Usage: /upload <path> @username [caption]");
                continue;
            }

            if (target_str.starts_with("@")) target_str.erase(0, 1);
            if (!caption.empty() && caption[0] == ' ') caption.erase(0, 1);

            if (!fs::exists(path)) {
                std::println("Error: File not found: {}", path);
                continue;
            }

            std::println("Resolving @{}...", target_str);
            auto remote = router.lookup_user(target_str);

            if (remote) {
                std::println("Queuing upload: {} -> @{}", path, remote->username);
                transfers.queue_upload(path, *remote, caption);
            } else {
                std::println("Error: User @{} not found.", target_str);
            }
        }
        else {
            std::println("Unknown command.");
        }
    }

    // 8. Cleanup
    std::println("Shutting down...");
    ipc.stop();
    transfers.stop();
    router.stop();
    db.close();
    return 0;
}