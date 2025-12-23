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

IPCServer::IPCServer(Router& router, TransferManager& transfers)
    : router_(router), transfers_(transfers) {}

IPCServer::~IPCServer() { stop(); }

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
        // PAIR socket: Exclusive 1-to-1 connection
        zmq::socket_t socket(ctx_, zmq::socket_type::pair);
        socket.bind("tcp://127.0.0.1:9002");

        std::println("[IPC] Server listening on tcp://127.0.0.1:9002");

        while (running_) {
            // We need to poll:
            // 1. Incoming ZMQ messages (Commands from GUI)
            // 2. Outgoing Queue (Events to GUI)

            // Since we can't select() on a std::queue easily, we use a timeout poll
            // This is "good enough" for UI latency (10-50ms)

            zmq::pollitem_t items[] = {
                { static_cast<void*>(socket), 0, ZMQ_POLLIN, 0 }
            };

            // Poll for 20ms
            zmq::poll(items, 1, std::chrono::milliseconds(20));

            // 1. Handle Incoming Command
            if (items[0].revents & ZMQ_POLLIN) {
                zmq::message_t msg;
                if (socket.recv(msg, zmq::recv_flags::none)) {
                    try {
                        auto j = json::parse(msg.to_string());
                        if (j.contains("command")) {
                            handle_command(j);
                        }
                    } catch (const std::exception& e) {
                        std::println(stderr, "[IPC] JSON Parse Error: {}", e.what());
                    }
                }
            }

            // 2. Flush Outgoing Events
            std::queue<std::string> outgoing;
            {
                std::lock_guard lock(queue_mutex_);
                outgoing.swap(event_queue_); // Take all
            }

            while (!outgoing.empty()) {
                std::string s = outgoing.front();
                outgoing.pop();
                socket.send(zmq::buffer(s), zmq::send_flags::dontwait);
            }
        }
    } catch (const zmq::error_t& e) {
        // Context closed or error
    }
}

void IPCServer::handle_command(const json& j) {
    std::string cmd = j["command"];
    const auto& p = j["payload"];

    std::println("[IPC] Cmd: {}", cmd);

    if (cmd == "send_text") {
        // { "target": "@bob", "text": "hello" }
        std::string target = p["target"];
        std::string text = p["text"];

        // Strip @
        if (target.starts_with("@")) target.erase(0, 1);

        // Async resolve & send
        // Note: In a real app we might want to return success/fail via IPC
        // For now we fire and forget or let Router logs handle it
        // TODO
        auto remote = router_.lookup_user(target);
        if (remote) {
            router_.send_text(*remote, text);
        }
    }
    else if (cmd == "upload_file") {
        // { "target": "@bob", "filepath": "..." }
        std::string target = p["target"];
        std::string path = p["filepath"];
        if (target.starts_with("@")) target.erase(0, 1);

        auto remote = router_.lookup_user(target);
        if (remote) {
            transfers_.queue_upload(path, *remote, "");
        }
    }
    else if (cmd == "quit") {
        running_ = false;
        std::exit(0);
    }
}

} // namespace nest