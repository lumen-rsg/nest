#include "router.hpp"
#include <iostream>
#include <print>
#include <chrono>
#include <format>

#include "common/file_crypto.hpp"

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

    bool Router::send_payload(const RemoteUser& target, const venom::Payload& payload) {
    // 1. Serialize Payload
    std::string payload_bytes;
    payload.SerializeToString(&payload_bytes);
    std::vector<uint8_t> payload_raw(payload_bytes.begin(), payload_bytes.end());

    // 2. Encrypt (AES-GCM)
    auto eph_keys = *crypto::generate_ephemeral_key();
    auto secret = *crypto::derive_secret(eph_keys.private_key, target.enc_key);
    auto enc_res = *crypto::encrypt_aes_gcm(payload_raw, secret);

    // Split
    std::vector<uint8_t> nonce(enc_res.begin(), enc_res.begin() + 12);
    std::vector<uint8_t> cipher(enc_res.begin() + 12, enc_res.end());

    // Sign
    auto sig = *crypto::sign(cipher, identity_.private_key);

    // 3. Create Envelope
    venom::Envelope env;
    env.set_sender_identity_key(to_str(identity_.public_key));
    env.set_ephemeral_pubkey(to_str(eph_keys.public_key));
    env.set_nonce(to_str(nonce));
    env.set_ciphertext(to_str(cipher));
    env.set_signature(to_str(sig));

    // 4. Create Packet
    venom::Packet packet = create_packet(venom::Packet::SEND);
    packet.set_target_id_pubkey(to_str(target.id_key));
    *packet.mutable_envelope() = env;
    sign_packet(packet);

    // 5. Send
    venom::Response resp;
    return send_request(packet, resp);
}

    // Update send_text to be a wrapper
    bool Router::send_text(const RemoteUser& target, const std::string& text) {
    venom::Payload p;
    p.set_type(venom::Payload::TEXT);
    p.set_timestamp(time(nullptr));
    p.set_body(text);
    return send_payload(target, p);
}

void Router::polling_loop() {
    std::println("[Router] Polling Hive at {}...", server_addr_);
    while (running_) {
        try {
            zmq::socket_t sock(ctx_, zmq::socket_type::req);
            sock.connect(server_addr_);

            // 1. Send FETCH
            auto p = create_packet(venom::Packet::FETCH);
            sign_packet(p);

            std::string p_data; p.SerializeToString(&p_data);
            sock.send(zmq::buffer(p_data), zmq::send_flags::none);

            zmq::message_t reply;
            sock.set(zmq::sockopt::rcvtimeo, 2000);

            std::vector<uint64_t> successful_ids;

            if (sock.recv(reply, zmq::recv_flags::none)) {
                venom::Response resp;
                if (resp.ParseFromArray(reply.data(), reply.size()) && resp.status() == 200) {

                    // 2. Process Messages
                    for (const auto& fm : resp.fetched_messages()) {
                        uint64_t s_id = fm.server_id();

                        // Try to process
                        if (process_inbound_envelope(fm.envelope())) {
                            successful_ids.push_back(s_id);
                        } else {
                            std::println(stderr, "[Router] Failed to process msg ID {}. Will NOT Ack.", s_id);
                            // It will remain on server and be redelivered next poll.
                            // In future, maybe implement a "poison pill" limit.
                        }
                    }
                }
            }

            // 3. Send ACK (if we processed anything)
            if (!successful_ids.empty()) {
                // We need a NEW socket or reconnect for the next request in ZMQ REQ/REP pattern
                // REQ sockets are strictly Send->Recv. We cannot Send->Recv->Send on the same connection object easily
                // without the server expecting it.
                // Easiest way: Re-create socket or just loop again immediately?
                // Let's just create a quick ACK request here.

                sock.close(); // Reset
                zmq::socket_t ack_sock(ctx_, zmq::socket_type::req);
                ack_sock.connect(server_addr_);

                auto ack_pkt = create_packet(venom::Packet::ACK);
                for (uint64_t id : successful_ids) {
                    ack_pkt.add_ack_ids(id);
                }
                sign_packet(ack_pkt);

                std::string ack_data; ack_pkt.SerializeToString(&ack_data);
                ack_sock.send(zmq::buffer(ack_data), zmq::send_flags::none);

                // Wait for ACK response (just to clean up socket state)
                zmq::message_t dummy;
                ack_sock.recv(dummy, zmq::recv_flags::none);
            }

        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

bool Router::process_inbound_envelope(const venom::Envelope& env) {
    auto sender_id = to_vec(env.sender_identity_key());
    auto eph_pub = to_vec(env.ephemeral_pubkey());
    auto cipher = to_vec(env.ciphertext());
    auto sig = to_vec(env.signature());
    auto nonce = to_vec(env.nonce());

    // Verify Sender
    if (!crypto::verify(cipher, sig, sender_id)) {
        std::println(stderr, "[Router] Invalid inner signature.");
        return false;
    }

    // Decrypt (My X25519 Priv + Sender Eph X25519 Pub)
    auto secret_res = crypto::derive_secret(enc_identity_.private_key, eph_pub);
    if (!secret_res) return false;

    std::vector<uint8_t> combined = nonce;
    combined.insert(combined.end(), cipher.begin(), cipher.end());

    auto plain = crypto::decrypt_aes_gcm(combined, *secret_res);
    if (!plain) return false;

    venom::Payload p;
    if (p.ParseFromArray(plain->data(), static_cast<int>(plain->size()))) {
        if (on_message_) on_message_(to_hex(sender_id), p);
        return true; // SUCCESS
    }
    return false;
}

    std::optional<RemoteUser> Router::lookup_user_by_id(const std::string& id_hex) {
    venom::Packet p = create_packet(venom::Packet::LOOKUP_USER_BY_ID);

    // Convert the Hex Input (e.g., "a1b2...") to Raw Bytes for the packet
    std::vector<uint8_t> raw_id = from_hex(id_hex);
    p.set_lookup_user_id(to_str(raw_id));

    sign_packet(p);

    try {
        zmq::socket_t sock(ctx_, zmq::socket_type::req);
        sock.connect(server_addr_);

        std::string p_data;
        p.SerializeToString(&p_data);
        sock.send(zmq::buffer(p_data), zmq::send_flags::none);

        zmq::message_t reply;
        sock.set(zmq::sockopt::rcvtimeo, 2000); // 2s timeout

        if (sock.recv(reply, zmq::recv_flags::none)) {
            venom::Response resp;
            if (resp.ParseFromArray(reply.data(), static_cast<int>(reply.size()))) {
                if (resp.status() == 200 && resp.has_user_info()) {
                    const auto& u = resp.user_info();
                    return RemoteUser{
                        u.username(),
                        to_vec(u.id_pubkey()),
                        to_vec(u.enc_pubkey())
                    };
                }
            }
        }
    } catch (...) {
        // Network error
    }
    return std::nullopt;
}


bool Router::send_request(venom::Packet& p, venom::Response& out_resp) {
    // 1. Sign
    sign_packet(p);

    // 2. Serialize
    std::string p_data;
    if (!p.SerializeToString(&p_data)) return false;

    // 3. Network Op (Blocking)
    try {
        zmq::socket_t sock(ctx_, zmq::socket_type::req);
        sock.connect(server_addr_);
        sock.send(zmq::buffer(p_data), zmq::send_flags::none);

        zmq::message_t reply;
        sock.set(zmq::sockopt::rcvtimeo, 5000); // 5s timeout default

        if (!sock.recv(reply, zmq::recv_flags::none)) return false;

        // 4. Parse
        if (!out_resp.ParseFromArray(reply.data(), static_cast<int>(reply.size()))) return false;

        return (out_resp.status() == 200);

    } catch (...) {
        return false;
    }
}

// --- File Logic ---

bool Router::upload_file(const std::string& filepath, venom::Attachment& out_metadata) {
    using namespace nest::crypto;

    // 1. Init Local Encryption
    FileEncryptor encryptor(filepath);
    auto meta_res = encryptor.init();
    if (!meta_res) return false;
    FileMetadata meta = *meta_res;

    // 2. Request Upload Session
    std::string session_id;
    {
        venom::Packet p = create_packet(venom::Packet::UPLOAD_INIT);
        venom::Response resp;
        if (!send_request(p, resp)) return false;
        session_id = resp.session_id();
    }
    if (session_id.empty()) return false;

    std::println("  [Upload] Session: {}", session_id);

    // 3. Loop Chunks
    size_t total = encryptor.get_total_chunks();
    for (size_t i = 0; i < total; ++i) {
        auto chunk_res = encryptor.get_encrypted_chunk(i);
        if (!chunk_res) return false;

        venom::Packet p = create_packet(venom::Packet::UPLOAD_CHUNK);
        p.set_session_id(session_id);

        auto* ch = p.mutable_file_chunk();
        ch->set_chunk_index(static_cast<uint32_t>(i));
        ch->set_data(to_str(*chunk_res));

        venom::Response resp;
        if (!send_request(p, resp)) {
            std::println(stderr, "  [Upload] Failed at chunk {}/{}", i, total);
            return false;
        }
        if (i % 10 == 0) std::print("."); // Progress
    }

    // 4. Finalize
    std::string final_fid;
    {
        venom::Packet p = create_packet(venom::Packet::UPLOAD_FINALIZE);
        p.set_session_id(session_id);
        venom::Response resp;
        if (!send_request(p, resp)) return false;
        final_fid = resp.file_id();
    }

    // 5. Populate Metadata for the E2EE Message
    out_metadata.set_file_id(final_fid);
    out_metadata.set_filename(std::filesystem::path(filepath).filename().string());
    out_metadata.set_size_bytes(meta.file_size);
    out_metadata.set_key(to_str(meta.key));
    out_metadata.set_nonce(to_str(meta.nonce));
    out_metadata.set_total_chunks(static_cast<uint32_t>(total));

    return true;
}

bool Router::download_file(const venom::Attachment& att, const std::string& output_path) {
    using namespace nest::crypto;

    // 1. Init Local Decryptor
    FileDecryptor decryptor(output_path, to_vec(att.key()), to_vec(att.nonce()));
    if (!decryptor.init()) return false;

    std::println("  [Download] {} chunks...", att.total_chunks());

    // 2. Loop Chunks
    for (uint32_t i = 0; i < att.total_chunks(); ++i) {
        venom::Packet p = create_packet(venom::Packet::DOWNLOAD_CHUNK);
        p.set_file_id(att.file_id());
        p.mutable_file_chunk()->set_chunk_index(i);

        venom::Response resp;
        if (!send_request(p, resp)) return false;

        if (resp.has_file_chunk()) {
            auto enc_data = to_vec(resp.file_chunk().data());

            // Decrypt and Write to disk immediately
            auto res = decryptor.write_chunk(i, enc_data);
            if (!res) {
                std::println(stderr, "  [Download] Decrypt Fail Chunk {}", i);
                return false;
            }
        } else {
            return false;
        }
        if (i % 10 == 0) std::print(".");
    }
    std::println("\n  [Download] Complete.");
    return true;
}

} // namespace nest