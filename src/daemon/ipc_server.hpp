//
// Created by cv2 on 23.12.2025.
//

#pragma once
#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <zmq.hpp>
#include "common/json.hpp"

// Forward declarations to avoid circular includes
namespace nest { class Router; class TransferManager; }

namespace nest {

    using json = nlohmann::json;

    class IPCServer {
    public:
        IPCServer(Router& router, TransferManager& transfers);
        ~IPCServer();

        void start();
        void stop();

        // Call this from any thread to push an event to the GUI
        void broadcast_event(const std::string& type, const json& payload);

    private:
        void loop();
        void handle_command(const json& cmd);

        Router& router_;
        TransferManager& transfers_;

        std::atomic<bool> running_{false};
        std::jthread thread_;

        // Thread-safe Outbox (Events to GUI)
        std::mutex queue_mutex_;
        std::queue<std::string> event_queue_;

        // ZMQ Context
        zmq::context_t ctx_;
    };

} // namespace nest