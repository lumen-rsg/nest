#include "db.hpp"
#include <iostream>
#include <print>
#include <cstring>
#include <openssl/rand.h>

namespace nest {

Database::Database() = default;

Database::~Database() {
    close();
}

void Database::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool Database::open(const std::string& filepath, const std::string& password) {
    if (sqlite3_open(filepath.c_str(), &db_) != SQLITE_OK) {
        std::println(stderr, "Failed to open DB: {}", sqlite3_errmsg(db_));
        return false;
    }

    // Enable WAL for concurrency
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);

    if (!init_tables()) return false;
    if (!load_or_create_salt()) return false;

    auto res = crypto::derive_key_from_password(password, salt_);
    if (!res) {
        std::println(stderr, "FATAL: KDF Failed.");
        return false;
    }
    master_key_ = *res;
    return true;
}

bool Database::init_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value BLOB
        );
        -- FIX: Use 'name' (TEXT) instead of 'name_enc'
        CREATE TABLE IF NOT EXISTS contacts (
            pubkey TEXT PRIMARY KEY,
            name TEXT
        );
        CREATE TABLE IF NOT EXISTS messages (
            peer_key TEXT,
            body_enc BLOB,
            is_mine INTEGER,
            timestamp INTEGER,
            uuid TEXT UNIQUE,        -- New: Global ID
            reply_to_uuid TEXT       -- New: Parent ID
        );
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::println(stderr, "DB Init Error: {}", err);
        sqlite3_free(err);
        return false;
    }
    return true;
}

bool Database::load_or_create_salt() {
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, "SELECT value FROM config WHERE key='kdf_salt'", -1, &stmt, nullptr);
    int rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW) {
        const void* blob = sqlite3_column_blob(stmt, 0);
        int bytes = sqlite3_column_bytes(stmt, 0);
        salt_.assign((const uint8_t*)blob, (const uint8_t*)blob + bytes);
        sqlite3_finalize(stmt);
    } else {
        sqlite3_finalize(stmt);
        salt_.resize(16);
        RAND_bytes(salt_.data(), 16);

        sqlite3_prepare_v2(db_, "INSERT INTO config (key, value) VALUES ('kdf_salt', ?)", -1, &stmt, nullptr);
        sqlite3_bind_blob(stmt, 1, salt_.data(), static_cast<int>(salt_.size()), SQLITE_STATIC);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::println(stderr, "Failed to save salt");
            return false;
        }
        sqlite3_finalize(stmt);
    }
    return true;
}

// --- Crypto Helpers ---

std::vector<uint8_t> Database::encrypt_field(const std::string& text) {
    std::vector<uint8_t> data(text.begin(), text.end());
    auto res = crypto::encrypt_aes_gcm(data, master_key_);
    if (!res) return {};
    return *res;
}

std::vector<uint8_t> Database::encrypt_field(const std::vector<uint8_t>& data) {
    auto res = crypto::encrypt_aes_gcm(data, master_key_);
    if (!res) return {};
    return *res;
}

std::string Database::decrypt_string(const std::vector<uint8_t>& blob) {
    auto res = crypto::decrypt_aes_gcm(blob, master_key_);
    if (!res) return "DECRYPT_FAIL";
    return std::string(res->begin(), res->end());
}

std::vector<uint8_t> Database::decrypt_bytes(const std::vector<uint8_t>& blob) {
    auto res = crypto::decrypt_aes_gcm(blob, master_key_);
    if (!res) return {};
    return *res;
}

// --- Identity ---

bool Database::has_identity() {
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, "SELECT 1 FROM config WHERE key='id_priv'", -1, &stmt, nullptr);
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

bool Database::save_identity(const crypto::KeyPair& id_keys, const crypto::KeyPair& enc_keys, const std::string& name) {
    auto enc_priv = encrypt_field(id_keys.private_key);
    auto enc_pub  = encrypt_field(id_keys.public_key);
    auto enc_x_priv = encrypt_field(enc_keys.private_key);
    auto enc_x_pub  = encrypt_field(enc_keys.public_key);
    auto enc_name = encrypt_field(name);

    sqlite3_stmt* stmt;
    const char* sql = "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)";

    auto save = [&](const char* k, const std::vector<uint8_t>& v) {
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, k, -1, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, v.data(), static_cast<int>(v.size()), SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    };

    save("id_priv", enc_priv);
    save("id_pub", enc_pub);
    save("enc_priv", enc_x_priv);
    save("enc_pub", enc_x_pub);
    save("id_name", enc_name);
    return true;
}

std::optional<StoredIdentity> Database::load_identity() {
    if (!has_identity()) return std::nullopt;

    StoredIdentity id;
    sqlite3_stmt* stmt;
    const char* sql = "SELECT value FROM config WHERE key=?";

    auto load = [&](const char* k) -> std::vector<uint8_t> {
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, k, -1, SQLITE_STATIC);
        std::vector<uint8_t> res;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* b = sqlite3_column_blob(stmt, 0);
            int bytes = sqlite3_column_bytes(stmt, 0);
            res.assign((const uint8_t*)b, (const uint8_t*)b + bytes);
        }
        sqlite3_finalize(stmt);
        return res;
    };

    id.keys.private_key = decrypt_bytes(load("id_priv"));
    id.keys.public_key  = decrypt_bytes(load("id_pub"));
    id.enc_keys.private_key = decrypt_bytes(load("enc_priv"));
    id.enc_keys.public_key  = decrypt_bytes(load("enc_pub"));
    id.name = decrypt_string(load("id_name"));

    if (id.enc_keys.private_key.empty()) return std::nullopt;
    return id;
}

// FIX: Updated to match new schema (name TEXT)
bool Database::save_contact(const std::string& pubkey_hex, const std::string& name, const std::string& ip) {
    // Note: 'ip' is currently unused in the new schema, we drop it.

    sqlite3_stmt* stmt;
    // Insert into 'contacts' using 'name' not 'name_enc'
    const char* sql = "INSERT OR REPLACE INTO contacts (pubkey, name) VALUES (?, ?)";

    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, pubkey_hex.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, name.c_str(), -1, SQLITE_STATIC); // Plaintext Name

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE);
}

// FIX: Matches new schema (name TEXT)
    bool Database::save_message(const std::string& peer_key, const std::string& body, bool is_mine,
                                const std::string& uuid, const std::string& reply_uuid) {
    if (peer_key.empty()) return false;

    // 1. Force Insert Contact (Auto-Create)
    {
        sqlite3_stmt* stmt;
        const char* sql_contact = "INSERT OR IGNORE INTO contacts (pubkey, name) VALUES (?, ?)";

        if (sqlite3_prepare_v2(db_, sql_contact, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, peer_key.c_str(), -1, SQLITE_TRANSIENT);
            // Default placeholder name
            std::string placeholder = "Unknown[" + peer_key.substr(0, 4) + "]";
            sqlite3_bind_text(stmt, 2, placeholder.c_str(), -1, SQLITE_TRANSIENT);

            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    // 2. Save Message
    auto body_enc = encrypt_field(body);
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO messages (peer_key, body_enc, is_mine, timestamp, uuid, reply_to_uuid) VALUES (?, ?, ?, ?, ?, ?)";

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::println(stderr, "[DB] Msg Prepare Error: {}", sqlite3_errmsg(db_));
        return false;
    }

    sqlite3_bind_text(stmt, 1, peer_key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, body_enc.data(), body_enc.size(), SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, is_mine ? 1 : 0);
    sqlite3_bind_int64(stmt, 4, time(nullptr));
    sqlite3_bind_text(stmt, 5, uuid.c_str(), -1, SQLITE_TRANSIENT);       // New
    sqlite3_bind_text(stmt, 6, reply_uuid.c_str(), -1, SQLITE_TRANSIENT); // New

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE);
}

// FIX: Matches new schema
std::string Database::get_contact_name(const std::string& key_hex) {
    sqlite3_stmt* stmt;
    // Query 'name' column
    sqlite3_prepare_v2(db_, "SELECT name FROM contacts WHERE pubkey = ?", -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, key_hex.c_str(), -1, SQLITE_STATIC);

    std::string name;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* txt = (const char*)sqlite3_column_text(stmt, 0);
        if (txt) name = txt;
    }
    sqlite3_finalize(stmt);
    return name;
}

// FIX: Matches new schema
bool Database::set_contact_name(const std::string& key_hex, const std::string& name) {
    return save_contact(key_hex, name, ""); // Reuse save_contact logic
}

std::vector<StoredMessage> Database::get_chat_history(const std::string& peer_key) {
    std::vector<StoredMessage> history;
    sqlite3_stmt* stmt;
    const char* sql = "SELECT body_enc, is_mine, timestamp FROM messages WHERE peer_key = ? ORDER BY timestamp ASC";

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return history;
    }

    sqlite3_bind_text(stmt, 1, peer_key.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        StoredMessage msg;
        msg.sender_key = peer_key;

        const void* blob = sqlite3_column_blob(stmt, 0);
        int bytes = sqlite3_column_bytes(stmt, 0);
        std::vector<uint8_t> encrypted_body((const uint8_t*)blob, (const uint8_t*)blob + bytes);

        msg.body = decrypt_string(encrypted_body);
        msg.is_mine = (sqlite3_column_int(stmt, 1) != 0);
        msg.timestamp = static_cast<uint64_t>(sqlite3_column_int64(stmt, 2));

        history.push_back(msg);
    }
    sqlite3_finalize(stmt);
    return history;
}

// FIX: Config uses string for value? No, init_tables says value BLOB.
// Let's ensure consistency. Logic seems fine as it casts string to vector.
bool Database::set_config(const std::string& key, const std::string& value) {
    std::vector<uint8_t> val(value.begin(), value.end());
    sqlite3_stmt* stmt;
    const char* sql = "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)";
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, val.data(), val.size(), SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE);
}

std::string Database::get_config(const std::string& key) {
    sqlite3_stmt* stmt;
    const char* sql = "SELECT value FROM config WHERE key=?";
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    std::string res;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* b = sqlite3_column_blob(stmt, 0);
        int bytes = sqlite3_column_bytes(stmt, 0);
        if (b && bytes > 0) res.assign((const char*)b, bytes);
    }
    sqlite3_finalize(stmt);
    return res;
}

// FIX: Matches new schema
std::vector<Database::Contact> Database::get_contacts() {
    std::vector<Contact> list;
    sqlite3_stmt* stmt;
    // Query 'name' column
    if (sqlite3_prepare_v2(db_, "SELECT pubkey, name FROM contacts", -1, &stmt, nullptr) != SQLITE_OK) {
        std::println(stderr, "DB Error get_contacts: {}", sqlite3_errmsg(db_));
        return list;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string pk = (const char*)sqlite3_column_text(stmt, 0);
        const char* nm_ptr = (const char*)sqlite3_column_text(stmt, 1);
        std::string nm = nm_ptr ? nm_ptr : "Unknown";
        list.push_back({pk, nm, ""});
    }
    sqlite3_finalize(stmt);
    return list;
}

    bool Database::edit_message(const std::string& uuid, const std::string& new_body) {
    auto body_enc = encrypt_field(new_body);
    sqlite3_stmt* stmt;
    const char* sql = "UPDATE messages SET body_enc = ? WHERE uuid = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_blob(stmt, 1, body_enc.data(), body_enc.size(), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, uuid.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE);
}

    // New: Delete message
    bool Database::delete_message(const std::string& uuid) {
    sqlite3_stmt* stmt;
    const char* sql = "DELETE FROM messages WHERE uuid = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, uuid.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE);
}

} // namespace nest