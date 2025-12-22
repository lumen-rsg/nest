#include "router.hpp"
#include <iostream>
#include <print>
#include <chrono>
#include <format>

namespace nest {

// --- Helpers ---

// Helper: Hex String -> Bytes
static std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        bytes.push_back((uint8_t)strtol(byteString.c_str(), nullptr, 16));
    }
    return bytes;
}

// Helper: Bytes -> Hex String
static std::string to_hex(const std::vector<uint8_t>& data) {
    std::string s;
    for(auto b : data) s += std::format("{:02x}", b);
    return s;
}

// Helper: Bytes -> Proto String
static std::string to_str(const std::vector<uint8_t>& b) {
    return std::string(b.begin(), b.end());
}

// Helper: Proto String -> Bytes (The one you were missing)
static std::vector<uint8_t> to_vec(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// --- Implementation ---

Router::Router(crypto::KeyPair identity, crypto::KeyPair enc_identity, Database& db)
    : identity_(std::move(identity)), enc_identity_(std::move(enc_identity)), db_(db) {}

Router::~Router() { stop(); }

void Router::start(const std::string& server_ip, uint16_t server_port, OnMessageCallback callback) {
    on_message_ = std::move(callback);
    server_addr_ = "tcp://" + server_ip + ":" + std::to_string(server_port);
    running_ = true;
    poll_thread_ = std::jthread([this] { polling_loop(); });
}

void Router::stop() {
    running_ = false;
    ctx_.shutdown();
}

venom::Packet Router::create_packet(venom::Packet::Type type) {
    venom::Packet p;
    p.set_type(type);
    p.set_timestamp(static_cast<uint64_t>(std::time(nullptr)));
    p.set_sender_id_pubkey(to_str(identity_.public_key));
    return p;
}

void Router::sign_packet(venom::Packet& p) {
    // Sign: sender_key + timestamp
    std::string data_to_sign = p.sender_id_pubkey() + std::to_string(p.timestamp());
    std::vector<uint8_t> raw(data_to_sign.begin(), data_to_sign.end());
    auto sig = crypto::sign(raw, identity_.private_key);
    if (sig) p.set_signature(to_str(*sig));
}

bool Router::register_on_server(const std::string& username) {
    auto p = create_packet(venom::Packet::REGISTER);

    venom::RegisterPayload* reg = p.mutable_register_();
    reg->set_username(username);
    reg->set_enc_pubkey(to_str(enc_identity_.public_key)); // Publish X25519 Key

    sign_packet(p);

    try {
        zmq::socket_t sock(ctx_, zmq::socket_type::req);
        sock.connect(server_addr_);

        std::string p_data; p.SerializeToString(&p_data);
        sock.send(zmq::buffer(p_data), zmq::send_flags::none);

        zmq::message_t reply;
        sock.set(zmq::sockopt::rcvtimeo, 2000);
        if (sock.recv(reply, zmq::recv_flags::none)) {
            venom::Response resp;
            if (resp.ParseFromArray(reply.data(), static_cast<int>(reply.size()))) {
                if (resp.status() == 200) return true;
                std::println(stderr, "[Register] Failed: {}", resp.error_msg());
            }
        }
    } catch (...) {}
    return false;
}

std::optional<RemoteUser> Router::lookup_user(const std::string& username) {
    auto p = create_packet(venom::Packet::LOOKUP_USER);
    p.set_lookup_username(username);
    sign_packet(p);

    try {
        zmq::socket_t sock(ctx_, zmq::socket_type::req);
        sock.connect(server_addr_);

        std::string p_data; p.SerializeToString(&p_data);
        sock.send(zmq::buffer(p_data), zmq::send_flags::none);

        zmq::message_t reply;
        sock.set(zmq::sockopt::rcvtimeo, 2000);
        if (sock.recv(reply, zmq::recv_flags::none)) {
            venom::Response resp;
            if (resp.ParseFromArray(reply.data(), static_cast<int>(reply.size())) &&
                resp.status() == 200 && resp.has_user_info()) {

                const auto& u = resp.user_info();
                return RemoteUser{
                    u.username(),
                    to_vec(u.id_pubkey()),
                    to_vec(u.enc_pubkey())
                };
            }
        }
    } catch (...) {}
    return std::nullopt;
}

bool Router::send_text(const RemoteUser& target, const std::string& text) {
    // 1. Prepare Payload
    venom::Payload payload;
    payload.set_type(venom::Payload::TEXT);
    payload.set_timestamp(static_cast<uint64_t>(std::time(nullptr)));
    payload.set_body(text);

    std::string payload_bytes; payload.SerializeToString(&payload_bytes);
    std::vector<uint8_t> payload_raw(payload_bytes.begin(), payload_bytes.end());

    // 2. Encrypt (Using Target's X25519 Encryption Key)
    auto eph_keys = *crypto::generate_ephemeral_key();
    auto secret = *crypto::derive_secret(eph_keys.private_key, target.enc_key);
    auto enc_res = *crypto::encrypt_aes_gcm(payload_raw, secret); // [Nonce(12) + Cipher + Tag(16)]

    // Split for Proto
    std::vector<uint8_t> nonce(enc_res.begin(), enc_res.begin() + 12);
    std::vector<uint8_t> cipher(enc_res.begin() + 12, enc_res.end());

    // Sign the Ciphertext (Using MY Identity Key)
    auto sig = *crypto::sign(cipher, identity_.private_key);

    // 3. Create Envelope
    venom::Envelope env;
    env.set_sender_identity_key(to_str(identity_.public_key));
    env.set_ephemeral_pubkey(to_str(eph_keys.public_key));
    env.set_nonce(to_str(nonce));
    env.set_ciphertext(to_str(cipher));
    env.set_signature(to_str(sig));

    // 4. Wrap in Packet
    venom::Packet packet = create_packet(venom::Packet::SEND);

    // ROUTING: We route based on the Identity Key (Ed25519), not the Enc key
    packet.set_target_id_pubkey(to_str(target.id_key));

    *packet.mutable_envelope() = env;
    sign_packet(packet);

    // 5. Send
    try {
        zmq::socket_t sock(ctx_, zmq::socket_type::req);
        sock.connect(server_addr_);

        std::string p_data; packet.SerializeToString(&p_data);
        sock.send(zmq::buffer(p_data), zmq::send_flags::none);

        zmq::message_t reply;
        sock.set(zmq::sockopt::rcvtimeo, 2000);
        if (sock.recv(reply, zmq::recv_flags::none)) {
            venom::Response resp;
            if (resp.ParseFromArray(reply.data(), static_cast<int>(reply.size()))) {
                return resp.status() == 200;
            }
        }
    } catch (...) {}

    return false;
}

void Router::polling_loop() {
    std::println("[Router] Polling Hive at {}...", server_addr_);
    while (running_) {
        try {
            zmq::socket_t sock(ctx_, zmq::socket_type::req);
            sock.connect(server_addr_);

            auto p = create_packet(venom::Packet::FETCH);
            sign_packet(p);

            std::string p_data; p.SerializeToString(&p_data);
            sock.send(zmq::buffer(p_data), zmq::send_flags::none);

            zmq::message_t reply;
            sock.set(zmq::sockopt::rcvtimeo, 2000);
            auto res = sock.recv(reply, zmq::recv_flags::none);

            if (res) {
                venom::Response resp;
                if (resp.ParseFromArray(reply.data(), static_cast<int>(reply.size())) && resp.status() == 200) {
                    for (const auto& env : resp.pending_messages()) {
                        process_inbound_envelope(env);
                    }
                }
            }
        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void Router::process_inbound_envelope(const venom::Envelope& env) {
    auto sender_id = to_vec(env.sender_identity_key());
    auto eph_pub = to_vec(env.ephemeral_pubkey());
    auto cipher = to_vec(env.ciphertext());
    auto sig = to_vec(env.signature());
    auto nonce = to_vec(env.nonce());

    // Verify Sender
    if (!crypto::verify(cipher, sig, sender_id)) {
        std::println(stderr, "[Router] Invalid inner signature.");
        return;
    }

    // Decrypt (My X25519 Priv + Sender Eph X25519 Pub)
    auto secret_res = crypto::derive_secret(enc_identity_.private_key, eph_pub);
    if (!secret_res) return;

    std::vector<uint8_t> combined = nonce;
    combined.insert(combined.end(), cipher.begin(), cipher.end());

    auto plain = crypto::decrypt_aes_gcm(combined, *secret_res);
    if (!plain) return;

    venom::Payload p;
    if (p.ParseFromArray(plain->data(), static_cast<int>(plain->size()))) {
        if (on_message_) on_message_(to_hex(sender_id), p);
    }
}

} // namespace nest