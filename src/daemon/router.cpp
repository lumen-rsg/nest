//
// Created by cv2 on 22.12.2025.
//
#include "router.hpp"
#include <iostream>
#include <print>
#include <chrono>
#include <zmq.hpp>

namespace nest {

// Helper to convert hex string to bytes
static std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        bytes.push_back((uint8_t)strtol(byteString.c_str(), nullptr, 16));
    }
    return bytes;
}

// Helper to string
static std::string to_str(const std::vector<uint8_t>& b) {
    return std::string(b.begin(), b.end());
}

Router::Router(uint32_t port, crypto::KeyPair identity, crypto::KeyPair enc_identity, Database& db)
    : port_(port), identity_(std::move(identity)), enc_identity_(std::move(enc_identity)), db_(db) {}

Router::~Router() { stop(); }

void Router::start(OnMessageCallback callback) {
    on_message_ = std::move(callback);
    running_ = true;
    listen_thread_ = std::jthread([this] { listener_loop(); });
}

void Router::stop() {
    running_ = false;
    ctx_.shutdown(); // Break the ZMQ loop
}

void Router::listener_loop() {
    try {
        zmq::socket_t socket(ctx_, zmq::socket_type::router);
        // Bind to all interfaces
        std::string addr = "tcp://0.0.0.0:" + std::to_string(port_);
        socket.bind(addr);

        std::println("[Router] Listening for messages on {}", addr);

        while (running_) {
            zmq::message_t identity_frame;
            zmq::message_t payload_frame;

            // ZMQ Router receives: [Sender_ZMQ_ID] [Empty] [Data]
            // We usually receive 2 or 3 frames depending on ZMQ version/flags
            auto res = socket.recv(identity_frame, zmq::recv_flags::none);
            if (!res) break;

            // Sometimes ZMQ sends an empty delimiter frame?
            if (identity_frame.size() == 0) {
               // handle weirdness if necessary
            }

            // Read the actual data
            res = socket.recv(payload_frame, zmq::recv_flags::none);
            if (!res) break;

            std::vector<uint8_t> data(static_cast<uint8_t*>(payload_frame.data()),
                                      static_cast<uint8_t*>(payload_frame.data()) + payload_frame.size());

            process_envelope(data);
        }
    } catch (const zmq::error_t& e) {
        if (running_) std::println(stderr, "[Router] ZMQ Error: {}", e.what());
    }
}

void Router::process_envelope(const std::vector<uint8_t>& data) {
    venom::Envelope env;
    if (!env.ParseFromArray(data.data(), static_cast<int>(data.size()))) {
        std::println(stderr, "[Router] Failed to parse incoming envelope.");
        return;
    }

    // 1. Extract Raw Bytes directly (No Hex conversion needed here)
    std::vector<uint8_t> sender_id_raw(env.sender_identity_key().begin(), env.sender_identity_key().end());
    std::vector<uint8_t> eph_pub(env.ephemeral_pubkey().begin(), env.ephemeral_pubkey().end());
    std::vector<uint8_t> ciphertext(env.ciphertext().begin(), env.ciphertext().end());
    std::vector<uint8_t> signature(env.signature().begin(), env.signature().end());
    std::vector<uint8_t> nonce(env.nonce().begin(), env.nonce().end());

    // 2. Verify Signature (Integrity + Authenticity)
    // We verify the ciphertext itself to ensure it wasn't tampered with
    if (!crypto::verify(ciphertext, signature, sender_id_raw)) {
        std::println(stderr, "[Router] Invalid signature from sender.");
        return;
    }

    // 3. Derive Shared Secret (My Priv + Sender Ephemeral Pub)
    auto secret_res = crypto::derive_secret(enc_identity_.private_key, eph_pub);
    if (!secret_res) {
        std::println(stderr, "[Router] ECDH derivation failed.");
        return;
    }

    // 4. Decrypt
    // Reconstruct payload for GCM: [Nonce] [Ciphertext] [Tag - wait, tag is usually at end of ciphertext in our wrapper]
    // Our crypto wrapper expects: [Nonce (12)] + [Ciphertext + Tag]
    // The proto has Nonce separate. Let's combine.
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), nonce.begin(), nonce.end());
    combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());

    auto plain_res = crypto::decrypt_aes_gcm(combined, *secret_res);
    if (!plain_res) {
        std::println(stderr, "[Router] Decryption failed.");
        return;
    }

    // 5. Parse Payload
    venom::Payload payload;
    if (!payload.ParseFromArray(plain_res->data(), static_cast<int>(plain_res->size()))) {
        std::println(stderr, "[Router] Malformed payload.");
        return;
    }

    // 6. Notify / Store
    std::string sender_hex_str;
    for(auto b : sender_id_raw) sender_hex_str += std::format("{:02x}", b);

    // Store in DB (TODO: implement store_message in DB class)
    // db_.store_message(sender_hex_str, payload.body(), false);

    if (on_message_) {
        on_message_(sender_hex_str, payload);
    }
}

    bool Router::send_text(const std::string& target_ip, uint32_t target_port,
                       const std::string& target_enc_pubkey_hex, const std::string& text){

    // 1. Prepare Payload
    venom::Payload p;
    p.set_type(venom::Payload::TEXT);
    p.set_timestamp(static_cast<uint64_t>(std::time(nullptr)));
    p.set_body(text);

    std::string p_serialized;
    p.SerializeToString(&p_serialized);
    std::vector<uint8_t> p_bytes(p_serialized.begin(), p_serialized.end());

    // 2. ECDH Setup
    // A. Generate Ephemeral Key for this message
    auto eph_keys_res = crypto::generate_ephemeral_key();
    if (!eph_keys_res) return false;
    auto eph_keys = *eph_keys_res;

    // B. Get Target Public Key
    auto target_pub_bytes = from_hex(target_enc_pubkey_hex);

    // C. Derive Shared Secret (My Ephemeral Priv + Target Static Pub)
    auto secret_res = crypto::derive_secret(eph_keys.private_key, target_pub_bytes);
    if (!secret_res) return false;

    // 3. Encrypt
    auto encrypted_res = crypto::encrypt_aes_gcm(p_bytes, *secret_res);
    if (!encrypted_res) return false;

    // Split [Nonce (12)] [Ciphertext+Tag]
    std::vector<uint8_t> enc_blob = *encrypted_res;
    std::vector<uint8_t> nonce(enc_blob.begin(), enc_blob.begin() + 12);
    std::vector<uint8_t> cipher_tag(enc_blob.begin() + 12, enc_blob.end());

    // 4. Sign (Sign the Ciphertext to prove I sent it)
    auto sig_res = crypto::sign(cipher_tag, identity_.private_key);
    if (!sig_res) return false;

    // 5. Pack Envelope
    venom::Envelope env;
    env.set_sender_identity_key(to_str(identity_.public_key));
    env.set_ephemeral_pubkey(to_str(eph_keys.public_key)); // Critical for receiver to decrypt!
    env.set_nonce(to_str(nonce));
    env.set_ciphertext(to_str(cipher_tag));
    env.set_signature(to_str(*sig_res));

    std::string env_serialized;
    env.SerializeToString(&env_serialized);

    // 6. Send via ZMQ Dealer
    try {
        zmq::socket_t sock(ctx_, zmq::socket_type::dealer);
        // Connect with a short timeout? ZMQ connects asynchronously.
        std::string endpoint = "tcp://" + target_ip + ":" + std::to_string(target_port);
        sock.connect(endpoint);

        // Send
        sock.send(zmq::buffer(env_serialized), zmq::send_flags::none);

        // Give ZMQ a moment to flush before destroying socket (since we use ephemeral socket here)
        // In production, we should keep connections open in a map.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace nest