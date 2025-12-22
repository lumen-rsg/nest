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
    std::println("[Hive] Starting Server...");

    // 1. DB
    ServerDB db;
    if (!db.open("hive.db")) {
        std::println(stderr, "Failed to open hive.db");
        return 1;
    }

    // 2. ZMQ
    zmq::context_t ctx;
    zmq::socket_t socket(ctx, zmq::socket_type::rep);
    socket.bind("tcp://0.0.0.0:5555");
    std::println("[Hive] Listening on :5555");

    while (true) {
        zmq::message_t request;
        auto res = socket.recv(request, zmq::recv_flags::none);
        if (!res) break;

        venom::Packet packet;
        venom::Response response;
        response.set_status(200);

        if (!packet.ParseFromArray(request.data(), static_cast<int>(request.size()))) {
            response.set_status(400);
            response.set_error_msg("Malformed Packet");
        }
        else {
            // TODO: Validate Signature here!

            if (packet.type() == venom::Packet::REGISTER) {
                std::string username = packet.register_().username();
                auto enc_key = to_vec(packet.register_().enc_pubkey());
                auto id_key = to_vec(packet.sender_id_pubkey());

                std::println("[Hive] Register Request: @{}", username);

                if (db.lookup_by_username(username)) {
                    response.set_status(409); // Conflict
                    response.set_error_msg("Username taken");
                } else {
                    if (db.register_user(username, id_key, enc_key)) {
                        std::println("[Hive] Registered @{} successfully.", username);
                    } else {
                        response.set_status(500);
                    }
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
            else if (packet.type() == venom::Packet::SEND) {
                auto target = to_vec(packet.target_id_pubkey());
                std::string env_blob; packet.envelope().SerializeToString(&env_blob);

                db.store_message(target, env_blob);
                std::println("[Hive] Message routed to stored inbox.");
            }
            else if (packet.type() == venom::Packet::FETCH) {
                auto msgs = db.fetch_messages(to_vec(packet.sender_id_pubkey()));
                for (const auto& blob : msgs) {
                    venom::Envelope* env = response.add_pending_messages();
                    env->ParseFromString(blob);
                }
                if (!msgs.empty()) std::println("[Hive] Delivered {} messages.", msgs.size());
            }
        }

        std::string resp_str; response.SerializeToString(&resp_str);
        socket.send(zmq::buffer(resp_str), zmq::send_flags::none);
    }
    return 0;
}