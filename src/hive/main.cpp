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
#include "../common/file_crypto.hpp"

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
    std::println("           HIVE SERVER v1.1 (ACK)        ");
    std::println("=========================================");

    // 1. Initialize Database
    nest::ServerDB db;
    if (!db.open("hive.db")) {
        std::println(stderr, "Fatal: Failed to open hive.db");
        return 1;
    }

    // 2. Initialize File Storage
    nest::StorageEngine storage("hive_data");
    if (!storage.init()) {
        std::println(stderr, "Fatal: Failed to initialize storage directory.");
        return 1;
    }

    // 3. Initialize Network
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
        auto recv_res = socket.recv(request, zmq::recv_flags::none);
        if (!recv_res) break;

        venom::Packet packet;
        venom::Response response;
        response.set_status(200);

        if (!packet.ParseFromArray(request.data(), static_cast<int>(request.size()))) {
            response.set_status(400);
            response.set_error_msg("Malformed Protocol Buffer");
        }
        else {
            // --- VERIFY SIGNATURE ---
            std::string expected_data = packet.sender_id_pubkey() + std::to_string(packet.timestamp());
            std::vector<uint8_t> raw_payload(expected_data.begin(), expected_data.end());
            std::vector<uint8_t> signature = to_vec(packet.signature());
            std::vector<uint8_t> sender_pubkey = to_vec(packet.sender_id_pubkey());

            if (!nest::crypto::verify(raw_payload, signature, sender_pubkey)) {
                std::println(stderr, "[Hive] Auth Failed: Invalid Signature");
                response.set_status(401);
                response.set_error_msg("Authentication Failed");
            }
            else {
                // --- LOGIC DISPATCH ---

                // 1. REGISTRATION
                if (packet.type() == venom::Packet::REGISTER) {
                    std::string username = packet.register_().username();
                    auto enc_key = to_vec(packet.register_().enc_pubkey());
                    std::println("[Registry] Register: @{}", username);
                    if (!db.register_user(username, sender_pubkey, enc_key)) {
                        response.set_status(409); response.set_error_msg("Username taken");
                    }
                }

                // 2. LOOKUPS
                else if (packet.type() == venom::Packet::LOOKUP_USER) {
                    auto user = db.lookup_by_username(packet.lookup_username());
                    if (user) {
                        auto* info = response.mutable_user_info();
                        info->set_username(user->username);
                        info->set_id_pubkey(to_str(user->id_pubkey));
                        info->set_enc_pubkey(to_str(user->enc_pubkey));
                    } else response.set_status(404);
                }
                else if (packet.type() == venom::Packet::LOOKUP_USER_BY_ID) {
                    auto user = db.lookup_by_id(to_vec(packet.lookup_user_id()));
                    if (user) {
                        auto* info = response.mutable_user_info();
                        info->set_username(user->username);
                        info->set_id_pubkey(to_str(user->id_pubkey));
                        info->set_enc_pubkey(to_str(user->enc_pubkey));
                    } else response.set_status(404);
                }

                // 3. MESSAGING
                else if (packet.type() == venom::Packet::SEND) {
                    auto target_id = to_vec(packet.target_id_pubkey());
                    std::string env_blob;
                    packet.envelope().SerializeToString(&env_blob);
                    db.store_message(target_id, env_blob);
                }
                else if (packet.type() == venom::Packet::FETCH) {
                    // FIX: Use peek and fetched_messages (ACK System)
                    auto raw_msgs = db.fetch_messages_peek(sender_pubkey);

                    for (const auto& [id, blob] : raw_msgs) {
                        venom::FetchedMessage* fm = response.add_fetched_messages();
                        fm->set_server_id(static_cast<uint64_t>(id));
                        fm->mutable_envelope()->ParseFromString(blob);
                    }
                    if (!raw_msgs.empty()) {
                        std::println("[Msg] Sending {} pending messages to {}", raw_msgs.size(), to_hex(sender_pubkey).substr(0, 8));
                    }
                }
                else if (packet.type() == venom::Packet::ACK) {
                    // FIX: Handle Deletions
                    std::vector<uint64_t> ids;
                    for (uint64_t id : packet.ack_ids()) ids.push_back(id);
                    if (!ids.empty()) {
                        db.delete_messages(sender_pubkey, ids);
                        std::println("[Msg] ACK received for {} messages.", ids.size());
                    }
                }

                // 4. FILES
                else if (packet.type() == venom::Packet::UPLOAD_INIT) {
                    auto res = storage.begin_upload();
                    if (res) response.set_session_id(*res);
                    else { response.set_status(500); response.set_error_msg("Storage Error"); }
                }
                else if (packet.type() == venom::Packet::UPLOAD_CHUNK) {
                    if (!storage.append_chunk(packet.session_id(), to_vec(packet.file_chunk().data()))) {
                        response.set_status(500);
                    }
                }
                else if (packet.type() == venom::Packet::UPLOAD_FINALIZE) {
                    auto res = storage.finalize_upload(packet.session_id(), to_hex(sender_pubkey));
                    if (res) response.set_file_id(*res);
                    else response.set_status(500);
                }
                else if (packet.type() == venom::Packet::DOWNLOAD_CHUNK) {
                    uint32_t chunk_idx = packet.file_chunk().chunk_index();
                    uint64_t chunk_size = nest::crypto::ENCRYPTED_CHUNK_SIZE;
                    uint64_t offset = (uint64_t)chunk_idx * chunk_size;

                    auto data_res = storage.read_chunk(packet.file_id(), offset, chunk_size);
                    if (data_res) {
                        auto* chunk = response.mutable_file_chunk();
                        chunk->set_chunk_index(chunk_idx);
                        chunk->set_data(to_str(*data_res));
                    } else response.set_status(404);
                }
            }
        }

        std::string response_data;
        response.SerializeToString(&response_data);
        socket.send(zmq::buffer(response_data), zmq::send_flags::none);
    }
    return 0;
}