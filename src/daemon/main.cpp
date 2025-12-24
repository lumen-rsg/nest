#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <print>
#include <format>
#include <filesystem>
#include <condition_variable>
#include <mutex>

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

// --- Helpers ---

std::string to_hex(const std::vector<uint8_t>& data) {
    std::string s;
    for(auto b : data) s += std::format("{:02x}", b);
    return s;
}

// Global Auth State
std::mutex auth_mutex;
std::condition_variable auth_cv;
struct AuthData {
    bool ready = false;
    bool is_setup = false;
    std::string username;
    std::string password;
    std::string server_ip;
    std::string avatar;
    std::string bio;
} auth_state;

// --- Main ---

int main(int argc, char* argv[]) {
    std::println("=========================================");
    std::println("       NEST SECURE DAEMON (HEADLESS)     ");
    std::println("=========================================");

    // 1. Start IPC Server
    nest::IPCServer ipc;
    std::string db_path = "nest.db";

    // Callbacks
    ipc.on_unlock = [&](std::string pass) {
        std::lock_guard lock(auth_mutex);
        auth_state.password = pass;
        auth_state.is_setup = false;
        auth_state.ready = true;
        auth_cv.notify_one();
    };

    ipc.on_setup = [&](std::string user, std::string pass, std::string ip, std::string av, std::string bio) {
        std::lock_guard lock(auth_mutex);
        auth_state.username = user;
        auth_state.password = pass;
        auth_state.server_ip = ip;
        auth_state.avatar = av;
        auth_state.bio = bio;
        auth_state.is_setup = true;
        auth_state.ready = true;
        auth_cv.notify_one();
    };

    // NEW: Handle status query
    ipc.on_get_status = [&]() -> std::string {
        return fs::exists(db_path) ? "locked" : "setup_needed";
    };

    ipc.start();

    // 2. Auth Loop
    nest::Database db;
    std::string final_server_ip;

    nest::crypto::KeyPair my_keys;
    nest::crypto::KeyPair my_enc_keys;
    std::string my_name;

    while (true) {
        // Detect state
        bool db_exists = fs::exists(db_path);

        // Broadcast status to UI
        json status_ev;
        status_ev["status"] = db_exists ? "locked" : "setup_needed";
        ipc.broadcast_event("status", status_ev);

        std::println("[Main] Waiting for Auth (DB Exists: {})...", db_exists);

        // Wait for input
        std::unique_lock lock(auth_mutex);
        auth_cv.wait(lock, []{ return auth_state.ready; });
        lock.unlock(); // Release lock while processing

        bool success = false;

        if (auth_state.is_setup) {
            // --- SETUP MODE ---
            std::println("[Main] Processing Setup...");
            if (db_exists) fs::remove(db_path); // Overwrite previous DB

            if (db.open(db_path, auth_state.password)) {
                auto k1 = nest::crypto::generate_identity_key();
                auto k2 = nest::crypto::generate_ephemeral_key();

                if (k1 && k2) {
                    db.save_identity(*k1, *k2, auth_state.username);
                    db.set_config("server_ip", auth_state.server_ip);
                    db.set_config("avatar", auth_state.avatar);
                    db.set_config("bio", auth_state.bio);

                    // Load into memory
                    my_keys = *k1; my_enc_keys = *k2; my_name = auth_state.username;
                    final_server_ip = auth_state.server_ip;
                    success = true;
                }
            }
        }
        else {
            // --- UNLOCK MODE ---
            std::println("[Main] Processing Unlock...");
            if (!db_exists) {
                // UI sent unlock, but DB is gone? Force setup state.
                json err; err["msg"] = "Database not found. Please create account.";
                ipc.broadcast_event("auth_failed", err);
                // Loop again, next status broadcast will be 'setup_needed'
                auth_state.ready = false;
                continue;
            }

            if (db.open(db_path, auth_state.password)) {
                // VERIFY PASSWORD BY ATTEMPTING DECRYPTION
                auto id = db.load_identity();
                if (id) {
                    my_keys = id->keys;
                    my_enc_keys = id->enc_keys;
                    my_name = id->name;

                    final_server_ip = db.get_config("server_ip");
                    if (final_server_ip.empty()) final_server_ip = "127.0.0.1";

                    success = true;
                } else {
                    std::println(stderr, "[Main] Decryption failed (Wrong Password).");
                    db.close();
                }
            }
        }

        if (success) {
            break; // Proceed to services
        } else {
            std::println(stderr, "[Main] Auth/Setup Failed.");
            json err; err["msg"] = "Authentication Failed (Wrong Password?)";
            ipc.broadcast_event("auth_failed", err);

            // Reset and wait again
            auth_state.ready = false;
        }
    }

    // 3. Start Services
    std::println("[Main] Identity Loaded: @{}", my_name);

    nest::Router router(my_keys, my_enc_keys, db);
    nest::TransferManager transfers(router);
    nest::Notifier notifier("Nest");

    // Connect IPC to services
    ipc.set_services(&router, &transfers);
    ipc.set_identity(my_name, to_hex(my_keys.public_key));

    // Message Handler
    auto on_message = [&](const std::string& sender_hex, const venom::Payload& p) {
        std::string display_name = db.get_contact_name(sender_hex);
        if (display_name.empty()) {
            auto remote = router.lookup_user_by_id(sender_hex);
            if (remote) {
                display_name = remote->username;
                db.set_contact_name(sender_hex, display_name);
            } else display_name = "Unknown";
        }

        json j;
        j["sender"] = display_name;
        j["sender_key"] = sender_hex;
        j["timestamp"] = p.timestamp();

        std::string notif_body;

        if (p.type() == venom::Payload::TEXT) {
            j["type"] = "text";
            j["body"] = p.body();
            notif_body = p.body();
            std::println(">>> @{}: {}", display_name, p.body());
        }
        else if (p.type() == venom::Payload::MEDIA) {
            j["type"] = "media";
            j["filename"] = p.attachment().filename();
            // TODO: Pass full local path if downloaded
            notif_body = "Sent a file.";

            fs::create_directories("downloads");
            transfers.queue_download(p.attachment(), "downloads", display_name);
        }

        ipc.broadcast_event("new_message", j);
        notifier.notify("Message from @" + display_name, notif_body);
        db.save_message(sender_hex, p.body(), false);
    };

    router.start(final_server_ip, 5555, on_message);
    transfers.start();

    // Notify UI
    json info;
    info["username"] = my_name;
    info["pubkey"] = to_hex(my_keys.public_key);
    ipc.broadcast_event("ready", info);

    // Register with Hive
    router.register_on_server(my_name);

    std::println("[Main] Daemon Running.");

    // Keep alive
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}