#pragma once
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <vector>
#include <nlohmann/json.hpp>

// Standard networking includes
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "router.hpp"
#include "transfer_manager.hpp"
#include "../common/db.hpp"

using json = nlohmann::json;

namespace nest {

    class UIGateway {
    public:
        UIGateway(Router& router, TransferManager& transfers, Database& db);
        ~UIGateway();

        void start(uint16_t port = 5556);
        void stop();

        // Send an event to the UI
        void emit_event(const std::string& type, const json& data);

    private:
        void loop();
        void handle_command(const std::string& command_str);

        // Low-level write to socket
        void write_to_client(const std::string& data);

        Router& router_;
        TransferManager& transfers_;
        Database& db_;

        std::atomic<bool> running_{false};
        std::jthread thread_;

        // Socket state
        int server_fd_ = -1;
        int client_fd_ = -1;
    };

} // namespace nest