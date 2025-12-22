#include <iostream>
#include <print>
#include <thread>
#include <vector>
#include <string>
#include <format>
#include <zmq.hpp>

// Internal Headers
#include "venom.pb.h"
#include "server_db.hpp"
#include "storage.hpp"
#include "../common/crypto.hpp"
#include "../common/file_crypto.hpp" // Required for ENCRYPTED_CHUNK_SIZE

// --- Helpers ---

std::vector<uint8_t> to_vec(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::string to_str(const std::vector<uint8_t>& b) {
    return std::string(b.begin(), b.end());
}

std::string to_hex(const std::vector<uint8_t>& data) {
    std::string s;
    for(auto b : data) s += std::format("{:02x}", b);
    return s;
}

// --- Main Server Logic ---

int main() {
    std::println("=========================================");
    std::println("           HIVE SERVER v1.0              ");
    std::println("=========================================");

    // 1. Initialize Database
    nest::ServerDB db;
    if (!db.open("hive.db")) {
        std::println(stderr, "Fatal: Failed to open hive.db");
        return 1;
    }

    // 2. Initialize File Storage
    // Stores files in ./hive_data/store/ and ./hive_data/temp/
    nest::StorageEngine storage("hive_data");
    if (!storage.init()) {
        std::println(stderr, "Fatal: Failed to initialize storage directory.");
        return 1;
    }

    // 3. Initialize Network (ZeroMQ)
    zmq::context_t ctx;
    zmq::socket_t socket(ctx, zmq::socket_type::rep);

    try {
        socket.bind("tcp://0.0.0.0:5555");
        std::println("[Hive] Listening on tcp://0.0.0.0:5555");
    } catch (const zmq::error_t& e) {
        std::println(stderr, "[Hive] Bind failed: {}", e.what());
        return 1;
    }

    // 4. Main Request Loop
    while (true) {
        zmq::message_t request;

        // Block until a request arrives
        auto recv_res = socket.recv(request, zmq::recv_flags::none);
        if (!recv_res) break; // Context destroyed / Exit

        venom::Packet packet;
        venom::Response response;

        // Default to OK, overwrite on error
        response.set_status(200);

        // A. Parse Packet
        if (!packet.ParseFromArray(request.data(), static_cast<int>(request.size()))) {
            response.set_status(400);
            response.set_error_msg("Malformed Protocol Buffer");
        }
        else {
            // B. Verify Signature (Authentication)
            // Reconstruct the data that was signed: [SenderID_Bytes + Timestamp_String]
            std::string expected_data = packet.sender_id_pubkey() + std::to_string(packet.timestamp());
            std::vector<uint8_t> raw_payload(expected_data.begin(), expected_data.end());

            std::vector<uint8_t> signature = to_vec(packet.signature());
            std::vector<uint8_t> sender_pubkey = to_vec(packet.sender_id_pubkey());

            // Optional: Check timestamp freshness here (e.g., +/- 5 minutes)

            if (!nest::crypto::verify(raw_payload, signature, sender_pubkey)) {
                std::println(stderr, "[Hive] Auth Failed: Invalid Signature from {}", to_hex(sender_pubkey).substr(0, 8));
                response.set_status(401);
                response.set_error_msg("Authentication Failed: Invalid Signature");
            }
            else {
                // C. Logic Dispatch

                // --- USER REGISTRY ---
                if (packet.type() == venom::Packet::REGISTER) {
                    std::string username = packet.register_().username();
                    auto enc_key = to_vec(packet.register_().enc_pubkey());

                    std::println("[Registry] Register request: @{}", username);

                    // Attempt to register
                    if (db.register_user(username, sender_pubkey, enc_key)) {
                        std::println("[Registry] Success: @{}", username);
                    } else {
                        // Likely username collision
                        response.set_status(409);
                        response.set_error_msg("Username already taken");
                    }
                }
                else if (packet.type() == venom::Packet::LOOKUP_USER) {
                    std::string query = packet.lookup_username();
                    auto user = db.lookup_by_username(query);

                    if (user) {
                        auto* info = response.mutable_user_info();
                        info->set_username(user->username);
                        info->set_id_pubkey(to_str(user->id_pubkey));
                        info->set_enc_pubkey(to_str(user->enc_pubkey));
                    } else {
                        response.set_status(404);
                        response.set_error_msg("User not found");
                    }
                }
                else if (packet.type() == venom::Packet::LOOKUP_USER_BY_ID) {
                    auto search_id = to_vec(packet.lookup_user_id());
                    auto user = db.lookup_by_id(search_id);

                    if (user) {
                        auto* info = response.mutable_user_info();
                        info->set_username(user->username);
                        info->set_id_pubkey(to_str(user->id_pubkey));
                        info->set_enc_pubkey(to_str(user->enc_pubkey));
                    } else {
                        response.set_status(404);
                        response.set_error_msg("User ID not found");
                    }
                }

                // --- MESSAGING ---
                else if (packet.type() == venom::Packet::SEND) {
                    auto target_id = to_vec(packet.target_id_pubkey());

                    // Serialize the inner E2EE envelope to store it opaquely
                    std::string env_blob;
                    packet.envelope().SerializeToString(&env_blob);

                    db.store_message(target_id, env_blob);
                    // std::println("[Msg] Stored message for {}", to_hex(target_id).substr(0, 8));
                }
                else if (packet.type() == venom::Packet::FETCH) {
                    // Fetch messages for the signer
                    auto msgs = db.fetch_messages(sender_pubkey);

                    for (const auto& blob : msgs) {
                        venom::Envelope* env = response.add_pending_messages();
                        env->ParseFromString(blob);
                    }
                    if (!msgs.empty()) {
                        std::println("[Msg] Delivered {} messages to {}", msgs.size(), to_hex(sender_pubkey).substr(0, 8));
                    }
                }

                // --- FILE TRANSFER ---
                else if (packet.type() == venom::Packet::UPLOAD_INIT) {
                    // Start a new upload session
                    auto session_res = storage.begin_upload();
                    if (session_res) {
                        response.set_session_id(*session_res);
                        std::println("[File] Upload Init: Session {}", *session_res);
                    } else {
                        response.set_status(500);
                        response.set_error_msg("Storage Error: Init failed");
                    }
                }
                else if (packet.type() == venom::Packet::UPLOAD_CHUNK) {
                    std::string session_id = packet.session_id();
                    auto data = to_vec(packet.file_chunk().data());

                    auto res = storage.append_chunk(session_id, data);
                    if (!res) {
                        response.set_status(500);
                        response.set_error_msg("Storage Error: Write failed or Quota exceeded");
                    }
                }
                else if (packet.type() == venom::Packet::UPLOAD_FINALIZE) {
                    std::string session_id = packet.session_id();
                    std::string uploader_hex = to_hex(sender_pubkey);

                    auto res = storage.finalize_upload(session_id, uploader_hex);
                    if (res) {
                        std::string final_hash = *res;
                        response.set_file_id(final_hash);
                        std::println("[File] Upload Finalized: {}", final_hash);
                    } else {
                        response.set_status(500);
                        response.set_error_msg("Storage Error: Finalize failed (Hash check/Move)");
                    }
                }
                else if (packet.type() == venom::Packet::DOWNLOAD_CHUNK) {
                    std::string file_id = packet.file_id();
                    uint32_t chunk_idx = packet.file_chunk().chunk_index();

                    // Calculate Offset using the Shared Crypto Constants
                    // Note: Nest uses Encrypted Chunks = 64KB Data + 16B Tag
                    uint64_t chunk_size = nest::crypto::ENCRYPTED_CHUNK_SIZE;
                    uint64_t offset = (uint64_t)chunk_idx * chunk_size;

                    auto data_res = storage.read_chunk(file_id, offset, chunk_size);

                    if (data_res) {
                        auto* chunk = response.mutable_file_chunk();
                        chunk->set_chunk_index(chunk_idx);
                        chunk->set_data(to_str(*data_res));
                    } else {
                        response.set_status(404);
                        response.set_error_msg("File or Chunk not found");
                    }
                }
                else {
                    response.set_status(400);
                    response.set_error_msg("Unknown Packet Type");
                }
            }
        }

        // D. Send Response
        std::string response_data;
        if (response.SerializeToString(&response_data)) {
            socket.send(zmq::buffer(response_data), zmq::send_flags::none);
        } else {
            // Should never happen unless OOM
            std::println(stderr, "[Hive] Failed to serialize response!");
            // Try to send empty error
            socket.send(zmq::buffer(std::string{}), zmq::send_flags::none);
        }
    }

    return 0;
}