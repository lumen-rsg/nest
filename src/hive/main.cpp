#include <iostream>
#include <print>
#include <thread>
#include <vector>
#include <zmq.hpp>
#include "venom.pb.h"
#include "../common/crypto.hpp"
#include "server_db.hpp" // Include the new DB header

using namespace nest;

// Helper to str
std::string to_str(const std::vector<uint8_t>& b) { return std::string(b.begin(), b.end()); }
std::vector<uint8_t> to_vec(const std::string& s) { return std::vector<uint8_t>(s.begin(), s.end()); }

int main() {
    std::println("[Hive] Starting Secure Server...");
    ServerDB db;
    if (!db.open("hive.db")) return 1;

    zmq::context_t ctx;
    zmq::socket_t socket(ctx, zmq::socket_type::rep);
    socket.bind("tcp://0.0.0.0:5555");
    std::println("[Hive] Ready.");

    while (true) {
        zmq::message_t request;
        if (!socket.recv(request, zmq::recv_flags::none)) break;

        venom::Packet packet;
        venom::Response response;
        response.set_status(200);

        if (!packet.ParseFromArray(request.data(), static_cast<int>(request.size()))) {
            response.set_status(400); response.set_error_msg("Invalid Proto");
        } else {
            // --- 1. SIGNATURE VALIDATION ---
            std::string expected_data = packet.sender_id_pubkey() + std::to_string(packet.timestamp());
            std::vector<uint8_t> raw_data(expected_data.begin(), expected_data.end());
            std::vector<uint8_t> sig(packet.signature().begin(), packet.signature().end());
            std::vector<uint8_t> pubkey(packet.sender_id_pubkey().begin(), packet.sender_id_pubkey().end());

            // Check timestamp freshness (optional but recommended: allow +/- 5 mins)
            // uint64_t now = time(nullptr);
            // if (packet.timestamp() < now - 300 || packet.timestamp() > now + 300) { ... error ... }

            if (!nest::crypto::verify(raw_data, sig, pubkey)) {
                std::println(stderr, "[Hive] Auth Failed: Invalid Signature from a client.");
                response.set_status(401);
                response.set_error_msg("Invalid Signature");
            }
            else {
                // --- 2. LOGIC DISPATCH ---

                if (packet.type() == venom::Packet::REGISTER) {
                    std::string username = packet.register_().username();
                    auto enc_key = to_vec(packet.register_().enc_pubkey());
                    if (db.register_user(username, pubkey, enc_key)) {
                        std::println("[Hive] Registered @{}", username);
                    } else {
                        response.set_status(409); response.set_error_msg("Username taken");
                    }
                }
                else if (packet.type() == venom::Packet::LOOKUP_USER) {
                    auto user = db.lookup_by_username(packet.lookup_username());
                    if (user) {
                        auto* info = response.mutable_user_info();
                        info->set_username(user->username);
                        info->set_id_pubkey(to_str(user->id_pubkey));
                        info->set_enc_pubkey(to_str(user->enc_pubkey));
                    } else {
                        response.set_status(404);
                    }
                }
                else if (packet.type() == venom::Packet::LOOKUP_USER_BY_ID) {
                    // NEW: Reverse Lookup
                    auto user_id = to_vec(packet.lookup_user_id());
                    auto user = db.lookup_by_id(user_id); // You need to add this to ServerDB
                    if (user) {
                        auto* info = response.mutable_user_info();
                        info->set_username(user->username);
                        info->set_id_pubkey(to_str(user->id_pubkey));
                        info->set_enc_pubkey(to_str(user->enc_pubkey));
                    } else {
                        response.set_status(404);
                    }
                }
                else if (packet.type() == venom::Packet::SEND) {
                    auto target = to_vec(packet.target_id_pubkey());
                    std::string env; packet.envelope().SerializeToString(&env);
                    db.store_message(target, env);
                }
                else if (packet.type() == venom::Packet::FETCH) {
                    auto msgs = db.fetch_messages(pubkey);
                    for(const auto& m : msgs) {
                        venom::Envelope* env = response.add_pending_messages();
                        env->ParseFromString(m);
                    }
                }
            }
        }
        std::string r_str; response.SerializeToString(&r_str);
        socket.send(zmq::buffer(r_str), zmq::send_flags::none);
    }
    return 0;
}