#pragma once
#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <zmq.hpp>
#include "../common/json.hpp"
#include <functional>

namespace nest {

    class Router;
    class TransferManager;

    using json = nlohmann::json;

    class IPCServer {
    public:
        IPCServer();
        ~IPCServer();

        void start();
        void stop();

        void set_services(Router* router, TransferManager* transfers);
        void set_identity(const std::string& username, const std::string& pubkey_hex);
        void broadcast_event(const std::string& type, const json& payload);

        // Callbacks
        std::function<void(std::string)> on_unlock;
        std::function<void(std::string, std::string, std::string, std::string, std::string)> on_setup;

        // NEW: Callback to query status from main thread
        std::function<std::string()> on_get_status;

    private:
        void loop();
        void handle_command(const json& cmd);

        Router* router_ = nullptr;
        TransferManager* transfers_ = nullptr;

        std::atomic<bool> running_{false};
        std::jthread thread_;

        std::mutex queue_mutex_;
        std::queue<std::string> event_queue_;
        zmq::context_t ctx_;

        std::string my_username_ = "Unknown";
        std::string my_pubkey_ = "";

        std::string last_client_id_;
    };

} // namespace nest