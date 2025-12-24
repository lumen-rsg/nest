//
// Created by cv2 on 23.12.2025.
//

#include "ipc_server.hpp"
#include "router.hpp"
#include "transfer_manager.hpp"
#include <iostream>
#include <print>
#include <chrono>

namespace nest {

    static std::string to_hex(const std::vector<uint8_t>& data) {
        std::string s;
        for(auto b : data) s += std::format("{:02x}", b);
        return s;
    }

    IPCServer::IPCServer() {}

    IPCServer::~IPCServer() { stop(); }

    void IPCServer::set_services(Router* router, TransferManager* transfers) {
        router_ = router;
        transfers_ = transfers;
    }

    void IPCServer::set_identity(const std::string& username, const std::string& pubkey_hex) {
        my_username_ = username;
        my_pubkey_ = pubkey_hex;
    }


void IPCServer::start() {
    running_ = true;
    thread_ = std::jthread([this] { loop(); });
}

void IPCServer::stop() {
    running_ = false;
    // Context shutdown breaks the blocking poll
    ctx_.shutdown();
}

void IPCServer::broadcast_event(const std::string& type, const json& payload) {
    json j;
    j["type"] = "event";
    j["event"] = type;
    j["payload"] = payload;

    std::string serialized = j.dump();

    {
        std::lock_guard lock(queue_mutex_);
        event_queue_.push(serialized);
    }
}

void IPCServer::loop() {
    try {
        zmq::socket_t socket(ctx_, zmq::socket_type::router);
        socket.bind("tcp://127.0.0.1:9002");

        std::println("[IPC] Server listening (ROUTER) on tcp://127.0.0.1:9002");

        while (running_) {
            zmq::pollitem_t items[] = {
                { static_cast<void*>(socket), 0, ZMQ_POLLIN, 0 }
            };
            zmq::poll(items, 1, std::chrono::milliseconds(20));

            // 1. Handle Incoming Command
            if (items[0].revents & ZMQ_POLLIN) {
                std::vector<zmq::message_t> frames;

                // --- ROBUST MULTIPART READ ---
                // Keep reading until there are no more frames (RCVMORE = 0)
                while (true) {
                    zmq::message_t& frame = frames.emplace_back();
                    if (!socket.recv(frame, zmq::recv_flags::none)) {
                        frames.pop_back(); // Should not happen if poll said POLLIN
                        break;
                    }
                    if (!socket.get(zmq::sockopt::rcvmore)) break;
                }

                if (frames.size() >= 2) {
                    // Frame 0: Identity (Always added by ROUTER)
                    const auto& id_frame = frames[0];
                    last_client_id_.assign(static_cast<const char*>(id_frame.data()), id_frame.size());

                    // The Payload is typically the LAST frame.
                    // (Skip empty delimiters if they exist in middle)
                    const auto& payload_frame = frames.back();

                    std::string payload_str(static_cast<const char*>(payload_frame.data()), payload_frame.size());

                    // Debug print to confirm receipt
                    std::println("[IPC] Recv from Client ID size {}: {}", last_client_id_.size(), payload_str);

                    try {
                        auto j = json::parse(payload_str);
                        if (j.contains("command")) {
                            handle_command(j);
                        }
                    } catch (const std::exception& e) {
                        std::println(stderr, "[IPC] JSON Parse Error: {}", e.what());
                    }
                } else {
                    std::println(stderr, "[IPC] Received weird packet with only {} frames", frames.size());
                }
            }

            // 2. Flush Outgoing Events
            std::queue<std::string> outgoing;
            {
                std::lock_guard lock(queue_mutex_);
                outgoing.swap(event_queue_);
            }

            // Only send if we have a connected client to route to
            if (!last_client_id_.empty() && !outgoing.empty()) {
                while (!outgoing.empty()) {
                    std::string s = outgoing.front();
                    outgoing.pop();

                    // ROUTER Send: [Identity] [Payload]
                    socket.send(zmq::buffer(last_client_id_), zmq::send_flags::sndmore);
                    socket.send(zmq::buffer(s), zmq::send_flags::dontwait);
                }
            }
        }
    } catch (const zmq::error_t& e) {
        std::println(stderr, "[IPC] Error: {}", e.what());
    }
}

void IPCServer::handle_command(const json& j) {
    std::string cmd = j["command"];
    // std::println("[IPC] Cmd: {}", cmd);

    // --- UNAUTHENTICATED COMMANDS ---
        if (cmd == "get_status") {
            json info;

            if (router_) {
                info["status"] = "ready";
            } else {
                // Ask main thread via callback to check DB existence
                if (on_get_status) {
                    info["status"] = on_get_status();
                } else {
                    info["status"] = "locked"; // Fallback default
                }
            }

            info["username"] = my_username_;
            broadcast_event("status", info);
        }
    else if (cmd == "unlock") {
        std::string pass = j["payload"].value("password", "");
        if (on_unlock && !pass.empty()) on_unlock(pass);
    }
    else if (cmd == "setup") {
        // DEBUG LOGGING
        std::println("[IPC] Processing setup command...");

        std::string user = j["payload"].value("username", "");
        std::string pass = j["payload"].value("password", "");
        std::string ip   = j["payload"].value("server_ip", "");
        std::string avatar = j["payload"].value("avatar", "");
        std::string bio    = j["payload"].value("bio", "");

        if (user.empty() || pass.empty() || ip.empty()) {
            std::println(stderr, "[IPC] Setup failed: Missing fields. User: {}, Pass: [hidden], IP: {}", user, ip);
            json err; err["msg"] = "Missing required fields";
            broadcast_event("auth_failed", err);
            return;
        }

        if (on_setup) {
            std::println("[IPC] Triggering on_setup callback...");
            on_setup(user, pass, ip, avatar, bio);
        } else {
            std::println(stderr, "[IPC] Critical: on_setup callback is null!");
        }
    }
    else if (cmd == "quit") {
        running_ = false;
        std::exit(0);
    }

    // --- AUTHENTICATED COMMANDS (Requires Router) ---
    else if (router_ && transfers_) {
        const auto& p = j["payload"];

     if (cmd == "add_contact") {
        // payload: { "username": "bob" }
        std::string username = j["payload"].value("username", "");
        if (username.starts_with("@")) username.erase(0, 1);

        if (!username.empty()) {
            // 1. Resolve Key from Server (to ensure valid user and get pubkey)
            auto remote = router_->lookup_user(username);
            if (remote) {
                // 2. Save to DB
                // We need access to DB. Router has it, but it's private.
                // Let's add a wrapper in Router or expose DB?
                // Better: Add router_->save_contact(username, key);
                router_->save_contact(remote->username, to_hex(remote->id_key));

                // Confirm to UI
                json evt; evt["username"] = remote->username;
                broadcast_event("contact_added", evt);
            } else {
                json err; err["msg"] = "User @" + username + " not found on Hive.";
                broadcast_event("error", err);
            }
        }
    }

        else if (cmd == "send_text") {
            std::string target = p["target"];
            std::string text = p["text"];
            if (target.starts_with("@")) target.erase(0, 1);

            // 1. Validate User Exists
            auto remote = router_->lookup_user(target);
            if (remote) {
                // 2. Send
                if (router_->send_text(*remote, text)) {
                    // Success: We rely on the client to have added it optimistically
                    // OR we can send a "message_sent" event confirmation
                } else {
                    json err; err["msg"] = "Failed to send message (Server Error)";
                    broadcast_event("error", err);
                }
            } else {
                // 3. User Not Found
                json err;
                err["msg"] = "User @" + target + " does not exist!";
                broadcast_event("error", err);
            }
        }
        else if (cmd == "upload_file") {
            std::string target = p["target"];
            std::string path = p["filepath"];
            if (target.starts_with("@")) target.erase(0, 1);

            auto remote = router_->lookup_user(target);
            if (remote) transfers_->queue_upload(path, *remote, "");
        }
        else if (cmd == "get_self") {
            json info;
            info["username"] = my_username_;
            info["pubkey"] = my_pubkey_;
            broadcast_event("ready", info);
        }
        else if (cmd == "sync_request") {
            json payload;
            payload["contacts"] = router_->get_all_chats();
            broadcast_event("sync_response", payload);
        }
    }
    else {
        // Command received but services not ready
        json err; err["msg"] = "Daemon is locked. Please unlock first.";
        broadcast_event("error", err);
    }
}

} // namespace nest