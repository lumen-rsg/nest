#include "beacon.hpp"
#include <iostream>
#include <print>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <chrono>

namespace nest {

BeaconService::BeaconService(uint32_t zmq_port, std::string name, crypto::KeyPair identity)
    : zmq_port_(zmq_port), display_name_(std::move(name)), identity_(std::move(identity)) {}

BeaconService::~BeaconService() {
    stop();
}

void BeaconService::start() {
    if (running_) return;
    running_ = true;
    std::println("[Beacon] Starting Secure Discovery on port {}", discovery_port_);
    broadcast_thread_ = std::jthread([this] { broadcast_loop(); });
    listen_thread_ = std::jthread([this] { listen_loop(); });
}

void BeaconService::stop() {
    running_ = false;
}

void BeaconService::broadcast_loop() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    int broadcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    struct sockaddr_in broadcast_addr{};
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(discovery_port_);
    broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;

    while (running_) {
        // 1. Create Beacon (Inner Data)
        venom::Beacon b;
        b.set_display_name(display_name_);
        b.set_port(zmq_port_);
        b.set_public_key(to_string(identity_.public_key));

        venom::Payload p;
        p.set_type(venom::Payload::BEACON);
        p.set_timestamp(static_cast<uint64_t>(time(nullptr)));
        *p.mutable_beacon_data() = b;

        std::string payload_bytes;
        p.SerializeToString(&payload_bytes);

        // 2. Sign the Payload
        // We sign the raw serialized payload.
        std::vector<uint8_t> data_to_sign(payload_bytes.begin(), payload_bytes.end());
        auto sig_res = crypto::sign(data_to_sign, identity_.private_key);

        if (sig_res) {
            // 3. Create Envelope (Outer Shell)
            venom::Envelope env;
            env.set_sender_identity_key(to_string(identity_.public_key));
            env.set_ciphertext(payload_bytes); // Unencrypted for Beacon
            env.set_signature(to_string(*sig_res));

            // Note: nonce is empty for beacons as we aren't encrypting

            std::string serialized_env;
            env.SerializeToString(&serialized_env);

            sendto(sock, serialized_env.data(), serialized_env.size(), 0,
                   (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
        } else {
            std::println(stderr, "[Beacon] Error signing beacon!");
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    close(sock);
}

void BeaconService::listen_loop() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    #ifdef SO_REUSEPORT
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    #endif

    struct sockaddr_in listen_addr{};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(discovery_port_);
    listen_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        close(sock);
        return;
    }

    struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    std::vector<char> buffer(65535); // Max UDP size

    while (running_) {
        struct sockaddr_in sender_addr{};
        socklen_t sender_len = sizeof(sender_addr);
        ssize_t len = recvfrom(sock, buffer.data(), buffer.size(), 0,
                               (struct sockaddr*)&sender_addr, &sender_len);

        if (len > 0) {
            // 1. Parse Envelope
            venom::Envelope env;
            if (!env.ParseFromArray(buffer.data(), static_cast<int>(len))) continue;

            // 2. Self-Discovery Check (Compare PubKeys)
            // Convert string to vector for comparison
            std::vector<uint8_t> sender_pk(env.sender_identity_key().begin(), env.sender_identity_key().end());

            if (sender_pk == identity_.public_key) continue; // Ignore ourselves

            // 3. Verify Signature
            std::vector<uint8_t> payload_bytes(env.ciphertext().begin(), env.ciphertext().end());
            std::vector<uint8_t> signature(env.signature().begin(), env.signature().end());

            if (!crypto::verify(payload_bytes, signature, sender_pk)) {
                std::println(stderr, "[Beacon] Dropped packet: Invalid Signature from {}", inet_ntoa(sender_addr.sin_addr));
                continue;
            }

            // 4. Parse Payload
            venom::Payload p;
            if (p.ParseFromString(env.ciphertext()) && p.type() == venom::Payload::BEACON) {
                const auto& b = p.beacon_data();

                std::string ip = inet_ntoa(sender_addr.sin_addr);

                // Optional: Verify that Envelope Sender == Beacon Sender
                if (b.public_key() != env.sender_identity_key()) {
                    std::println(stderr, "[Beacon] Spoof attempt? Env Key != Beacon Key");
                    continue;
                }

                std::lock_guard lock(peers_mutex_);
                peers_[ip] = Peer{
                    ip,
                    b.port(),
                    b.display_name(),
                    b.public_key(),
                    static_cast<uint64_t>(time(nullptr))
                };
            }
        }
    }
    close(sock);
}

    std::vector<Peer> BeaconService::get_peers() {
    std::lock_guard lock(peers_mutex_);
    std::vector<Peer> list;

    // Current time
    uint64_t now = static_cast<uint64_t>(time(nullptr));
    const uint64_t STALE_TIMEOUT_SECONDS = 30;

    // Iterate through map, prune stale peers, and collect active ones
    for (auto it = peers_.begin(); it != peers_.end(); ) {
        if (now - it->second.last_seen > STALE_TIMEOUT_SECONDS) {
            // Peer is effectively offline/gone
            it = peers_.erase(it);
        } else {
            list.push_back(it->second);
            ++it;
        }
    }

    return list;
}

} // namespace nest