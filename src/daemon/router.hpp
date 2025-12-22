#pragma once
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <optional>
#include <zmq.hpp>
#include "../common/crypto.hpp"
#include "../common/db.hpp"
#include "venom.pb.h"

namespace nest {

    struct RemoteUser {
        std::string username;
        std::vector<uint8_t> id_key;   // Ed25519 (Identity)
        std::vector<uint8_t> enc_key;  // X25519 (Encryption)
    };

    class Router {
    public:
        using OnMessageCallback = std::function<void(const std::string& sender_hex, const venom::Payload&)>;

        Router(crypto::KeyPair identity, crypto::KeyPair enc_identity, Database& db);
        ~Router();

        void start(const std::string& server_ip, uint16_t server_port, OnMessageCallback callback);
        void stop();

        // --- New Methods ---

        // Register my username/keys with the Hive
        bool register_on_server(const std::string& username);

        // Ask Hive for a user's keys
        std::optional<RemoteUser> lookup_user(const std::string& username);

        // Send E2EE message to a resolved user
        bool send_text(const RemoteUser& target, const std::string& text);
        std::optional<RemoteUser> lookup_user_by_id(const std::string& id_hex);

        // Upload a file securely
        bool upload_file(const std::string& filepath, venom::Attachment& out_metadata);

        // Download a file securely
        bool download_file(const venom::Attachment& att, const std::string& output_path);
        bool send_payload(const RemoteUser& target, const venom::Payload& payload);

    private:
        void polling_loop();
        venom::Packet create_packet(venom::Packet::Type type);
        void sign_packet(venom::Packet& p);
        void process_inbound_envelope(const venom::Envelope& env);
        bool send_request(venom::Packet& p, venom::Response& out_resp);

        crypto::KeyPair identity_;
        crypto::KeyPair enc_identity_;
        Database& db_;
        OnMessageCallback on_message_;

        std::string server_addr_;
        std::atomic<bool> running_{false};
        std::jthread poll_thread_;
        zmq::context_t ctx_;
    };

} // namespace nest