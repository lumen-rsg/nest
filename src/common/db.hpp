//
// Created by cv2 on 22.12.2025.
//

#pragma once
#include <string>
#include <vector>
#include <optional>
#include <sqlite3.h>
#include "crypto.hpp"

namespace nest {

    struct StoredIdentity {
        crypto::KeyPair keys;
        std::string name;
    };

    class Database {
    public:
        Database();
        ~Database();

        // Opens (or creates) the DB and derives the Master Key
        bool open(const std::string& filepath, const std::string& password);
        void close();

        // --- Identity Management ---
        // Check if we have a user registered
        bool has_identity();

        // Save my new identity (Encrypted)
        bool save_identity(const crypto::KeyPair& keys, const std::string& name);

        // Load my identity (Decrypted)
        std::optional<StoredIdentity> load_identity();


        // --- Contacts Management ---
        // Save a discovered peer
        bool save_contact(const std::string& pubkey_hex, const std::string& name, const std::string& ip);

        // Get all contacts
        struct Contact { std::string pubkey; std::string name; std::string ip; };
        std::vector<Contact> get_contacts();

    private:
        // Raw SQLite handle
        sqlite3* db_ = nullptr;

        // The key derived from password used to encrypt/decrypt table rows
        std::vector<uint8_t> master_key_;

        // Salt for KDF (stored in plain text in 'config' table)
        std::vector<uint8_t> salt_;

        // Helpers
        bool init_tables();
        bool load_or_create_salt();

        // Crypto Helpers for DB fields
        std::vector<uint8_t> encrypt_field(const std::string& text);
        std::vector<uint8_t> encrypt_field(const std::vector<uint8_t>& data);
        std::string decrypt_string(const std::vector<uint8_t>& blob);
        std::vector<uint8_t> decrypt_bytes(const std::vector<uint8_t>& blob);
    };

} // namespace nest