#include "ui_gateway.hpp"
#include <iostream>
#include <print>
#include <format>
#include <arpa/inet.h>
#include <cstring>
#include <vector>
#include <algorithm>

namespace nest {

// --- Helper Function ---
// (Moved here from main.cpp to be self-contained)
static std::string to_hex(const std::vector<uint8_t>& data) {
    std::string s;
    for(auto b : data) s += std::format("{:02x}", b);
    return s;
}

// --- Class Implementation ---

UIGateway::UIGateway(Router& r, TransferManager& t, Database& d)
    : router_(r), transfers_(t), db_(d) {}

UIGateway::~UIGateway() {
    stop();
}

void UIGateway::start(uint16_t port) {
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ == -1) {
        std::println(stderr, "[Gateway] Socket creation failed.");
        return;
    }

    int opt = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(port);

    if (bind(server_fd_, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::println(stderr, "[Gateway] Bind failed on port {}.", port);
        return;
    }

    if (listen(server_fd_, 1) < 0) {
        std::println(stderr, "[Gateway] Listen failed.");
        return;
    }

    running_ = true;
    std::println("[Gateway] UI TCP Server listening on 127.0.0.1:{}", port);
    thread_ = std::jthread([this] { loop(); });
}

void UIGateway::stop() {
    running_ = false;
    if (client_fd_ != -1) {
        shutdown(client_fd_, SHUT_RDWR);
        close(client_fd_);
    }
    if (server_fd_ != -1) {
        shutdown(server_fd_, SHUT_RDWR);
        close(server_fd_);
    }
}

void UIGateway::loop() {
    sockaddr_in client_address{};
    socklen_t addrlen = sizeof(client_address);

    while (running_) {
        std::println("[Gateway] Waiting for UI connection...");
        client_fd_ = accept(server_fd_, (struct sockaddr*)&client_address, &addrlen);

        if (client_fd_ < 0) {
            if (running_) std::println(stderr, "[Gateway] Accept failed.");
            continue;
        }
        std::println("[Gateway] UI connected.");

        std::vector<char> buffer;
        char read_buf[4096];

        while (running_) {
            ssize_t bytes_read = recv(client_fd_, read_buf, sizeof(read_buf), 0);
            if (bytes_read <= 0) {
                std::println("[Gateway] UI disconnected.");
                close(client_fd_);
                client_fd_ = -1;
                break;
            }

            buffer.insert(buffer.end(), read_buf, read_buf + bytes_read);

            while (buffer.size() >= 4) {
                uint32_t msg_len;
                memcpy(&msg_len, buffer.data(), 4);
                msg_len = ntohl(msg_len);

                if (buffer.size() >= 4 + msg_len) {
                    std::string msg_str(buffer.begin() + 4, buffer.begin() + 4 + msg_len);
                    handle_command(msg_str);
                    buffer.erase(buffer.begin(), buffer.begin() + 4 + msg_len);
                } else {
                    break;
                }
            }
        }
    }
}

void UIGateway::handle_command(const std::string& command_str) {
    try {
        json j = json::parse(command_str);
        std::string cmd = j.at("cmd").get<std::string>();

        // --- Command: Get My Info ---
        if (cmd == "get_my_info") {
            // This is a new helpful command for the UI on startup
            json info;
            info["username"] = db_.load_identity()->name; // Assuming identity exists
            info["id_key"] = to_hex(router_.get_identity().public_key);
            info["enc_key"] = to_hex(router_.get_enc_identity().public_key);
            emit_event("my_info", info);
        }
        // --- Command: Send Text Message ---
        else if (cmd == "send_text") {
            std::string target = j.at("target").get<std::string>();
            std::string text = j.at("text").get<std::string>();
            if (target.starts_with("@")) target.erase(0, 1);

            auto user = router_.lookup_user(target);
            if (user) {
                if (router_.send_text(*user, text)) {
                    db_.save_message(to_hex(user->id_key), text, true);
                    // Also emit the message back to the UI so it appears instantly
                    json j_msg;
                    j_msg["type"] = "text";
                    j_msg["content"] = text;
                    j_msg["is_mine"] = true;
                    j_msg["timestamp"] = time(nullptr);
                    j_msg["target_hex"] = to_hex(user->id_key);
                    emit_event("new_message", j_msg);
                }
            } else {
                emit_event("error", {{"msg", "User not found"}});
            }
        }
        // --- Command: Upload File ---
        else if (cmd == "upload_file") {
            std::string path = j.at("path").get<std::string>();
            std::string target = j.at("target").get<std::string>();
            std::string caption = j.value("caption", "");
            if (target.starts_with("@")) target.erase(0, 1);

            auto user = router_.lookup_user(target);
            if (user) {
                transfers_.queue_upload(path, *user, caption);
                emit_event("upload_queued", {{"path", path}});
            } else {
                emit_event("error", {{"msg", "User not found"}});
            }
        }
        // --- Command: Get Chat History ---
        else if (cmd == "get_history") {
            std::string target_hex = j.at("target_hex").get<std::string>();
            auto history = db_.get_chat_history(target_hex);

            json j_resp = json::array();
            for (const auto& msg : history) {
                j_resp.push_back({
                    {"body", msg.body},
                    {"is_mine", msg.is_mine},
                    {"timestamp", msg.timestamp},
                    {"sender_key", msg.sender_key}
                });
            }

            emit_event("history_result", {
                {"target_hex", target_hex},
                {"messages", j_resp}
            });
        }
        // --- Command: Lookup User ---
        else if (cmd == "lookup_user") {
            std::string target = j.at("target").get<std::string>();
            if (target.starts_with("@")) target.erase(0, 1);
            auto user = router_.lookup_user(target);
            if (user) {
                emit_event("lookup_result", {
                    {"username", user->username},
                    {"id_key", to_hex(user->id_key)},
                    {"enc_key", to_hex(user->enc_key)}
                });
            } else {
                emit_event("lookup_result", nullptr); // Indicate not found
            }
        }
    } catch (const std::exception& e) {
        emit_event("error", {{"msg", std::string("C++ Gateway Error: ") + e.what()}});
    }
}

void UIGateway::write_to_client(const std::string& data) {
    if (client_fd_ == -1 || !running_) return;

    uint32_t len = htonl(static_cast<uint32_t>(data.size()));

    // Use MSG_NOSIGNAL on Linux to prevent crashes if client disconnects abruptly
    #ifdef __linux__
        int flags = MSG_NOSIGNAL;
    #else
        int flags = 0;
    #endif

    ssize_t sent = send(client_fd_, &len, 4, flags);
    if (sent != 4) return;

    sent = send(client_fd_, data.c_str(), data.size(), flags);
    if (sent != static_cast<ssize_t>(data.size())) return;
}

void UIGateway::emit_event(const std::string& type, const json& data) {
    json j;
    j["type"] = type;
    j["payload"] = data;
    write_to_client(j.dump());
}

} // namespace nest