//
// Created by cv2 on 22.12.2025.
//

#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include "venom.pb.h"
#include "../common/crypto.hpp" // Include crypto

namespace nest {

    struct Peer {
        std::string ip;
        uint32_t port;
        std::string name;
        std::string public_key;     // Signing
        std::string enc_public_key; // Encryption <-- NEW
        uint64_t last_seen;
    };

    class BeaconService {
    public:
        // Change: Pass the full KeyPair instead of just a string
        BeaconService(uint32_t port, std::string name, crypto::KeyPair identity, crypto::KeyPair enc_identity);
        ~BeaconService();

        void start();
        void stop();

        std::vector<Peer> get_peers();

    private:
        void broadcast_loop();
        void listen_loop();

        // Helpers
        // Helper to serialize bytes for Protobuf
        static std::string to_string(const std::vector<uint8_t>& bytes) {
            return std::string(bytes.begin(), bytes.end());
        }

        uint32_t zmq_port_;
        std::string display_name_;

        // Change: Store the keys
        crypto::KeyPair identity_;     // Ed25519
        crypto::KeyPair enc_identity_; // X25519 <-- NEW

        const int discovery_port_ = 4444;

        std::atomic<bool> running_{false};
        std::jthread broadcast_thread_;
        std::jthread listen_thread_;

        std::mutex peers_mutex_;
        std::map<std::string, Peer> peers_;
    };

} // namespace nest} // namespace nest