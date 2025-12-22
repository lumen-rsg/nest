//
// Created by cv2 on 22.12.2025.
//

#pragma once
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <zmq.hpp> // cppzmq wrapper
#include "../common/crypto.hpp"
#include "../common/db.hpp"
#include "venom.pb.h"

namespace nest {

    class Router {
    public:
        // Callback when a new valid message is received/decrypted
        using OnMessageCallback = std::function<void(const std::string& sender_pk, const venom::Payload&)>;

        Router(uint32_t port, crypto::KeyPair identity, Database& db);
        ~Router();

        void start(OnMessageCallback callback);
        void stop();

        // Send a text message to a specific peer (by IP and PubKey)
        bool send_text(const std::string& target_ip, uint32_t target_port,
                       const std::string& target_pubkey_hex, const std::string& text);

    private:
        void listener_loop();

        // Handling incoming
        void process_envelope(const std::vector<uint8_t>& data);

        uint32_t port_;
        crypto::KeyPair identity_;
        Database& db_;
        OnMessageCallback on_message_;

        std::atomic<bool> running_{false};
        std::jthread listen_thread_;

        // ZMQ Context (Shared)
        zmq::context_t ctx_;
    };

} // namespace nest