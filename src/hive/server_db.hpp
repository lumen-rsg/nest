//
// Created by cv2 on 23.12.2025.
//

#pragma once
#include <string>
#include <vector>
#include <sqlite3.h>
#include <optional>
#include <print>
#include "../common/crypto.hpp"

namespace nest {

struct DBUserInfo {
    std::string username;
    std::vector<uint8_t> id_pubkey;
    std::vector<uint8_t> enc_pubkey;
};

class ServerDB {
public:
    ServerDB() = default;
    ~ServerDB() { if(db_) sqlite3_close(db_); }

    bool open(const std::string& path) {
        if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) return false;
        return init_tables();
    }

    bool init_tables() {
        const char* sql = R"(
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                id_pubkey BLOB UNIQUE,
                enc_pubkey BLOB,
                created_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS inbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_pubkey BLOB,
                envelope_blob BLOB,
                created_at INTEGER
            );
        )";
        char* err = nullptr;
        if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
            std::println(stderr, "DB Error: {}", err);
            sqlite3_free(err);
            return false;
        }
        return true;
    }

    // --- User Registry ---

    bool register_user(const std::string& username, const std::vector<uint8_t>& id_key, const std::vector<uint8_t>& enc_key) {
        sqlite3_stmt* stmt;
        const char* sql = "INSERT INTO users (username, id_pubkey, enc_pubkey, created_at) VALUES (?, ?, ?, ?)";
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, id_key.data(), id_key.size(), SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 3, enc_key.data(), enc_key.size(), SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 4, time(nullptr));

        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return (rc == SQLITE_DONE);
    }

    std::optional<DBUserInfo> lookup_by_username(const std::string& username) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT id_pubkey, enc_pubkey FROM users WHERE username = ?";
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

        std::optional<DBUserInfo> res;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            res = DBUserInfo{username, {}, {}};

            const void* b1 = sqlite3_column_blob(stmt, 0); int s1 = sqlite3_column_bytes(stmt, 0);
            res->id_pubkey.assign((const uint8_t*)b1, (const uint8_t*)b1 + s1);

            const void* b2 = sqlite3_column_blob(stmt, 1); int s2 = sqlite3_column_bytes(stmt, 1);
            res->enc_pubkey.assign((const uint8_t*)b2, (const uint8_t*)b2 + s2);
        }
        sqlite3_finalize(stmt);
        return res;
    }

    // --- Inbox ---

    void store_message(const std::vector<uint8_t>& target_id, const std::string& envelope_blob) {
        sqlite3_stmt* stmt;
        const char* sql = "INSERT INTO inbox (target_pubkey, envelope_blob, created_at) VALUES (?, ?, ?)";
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_blob(stmt, 1, target_id.data(), target_id.size(), SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, envelope_blob.data(), envelope_blob.size(), SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, time(nullptr));
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    std::vector<std::string> fetch_messages(const std::vector<uint8_t>& my_id) {
        std::vector<std::string> msgs;
        sqlite3_stmt* stmt;

        // 1. Select
        const char* sql = "SELECT id, envelope_blob FROM inbox WHERE target_pubkey = ?";
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_blob(stmt, 1, my_id.data(), my_id.size(), SQLITE_STATIC);

        std::vector<int64_t> ids_to_delete;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            ids_to_delete.push_back(sqlite3_column_int64(stmt, 0));
            const void* b = sqlite3_column_blob(stmt, 1); int s = sqlite3_column_bytes(stmt, 1);
            msgs.emplace_back((const char*)b, s);
        }
        sqlite3_finalize(stmt);

        // 2. Delete
        for (auto id : ids_to_delete) {
            char del_sql[64]; snprintf(del_sql, 64, "DELETE FROM inbox WHERE id=%lld", id);
            sqlite3_exec(db_, del_sql, nullptr, nullptr, nullptr);
        }

        return msgs;
    }

private:
    sqlite3* db_ = nullptr;
};

} // namespace nest