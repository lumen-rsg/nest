//
// Created by cv2 on 23.12.2025.
//

#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <expected>
#include <filesystem>
#include "crypto.hpp"

namespace nest::crypto {

    // Standard chunk size for file transfer (64KB)
    // Small enough for network packets, large enough for efficiency.
    constexpr size_t FILE_CHUNK_SIZE = 64 * 1024;
    constexpr size_t GCM_TAG_SIZE = 16;
    // The encrypted chunk size = Data + Tag
    constexpr size_t ENCRYPTED_CHUNK_SIZE = FILE_CHUNK_SIZE + GCM_TAG_SIZE;

    enum class FileError {
        OpenFailed,
        ReadFailed,
        WriteFailed,
        CryptoFailed,
        InvalidSize
    };

    struct FileMetadata {
        Bytes key;   // 32-byte AES key (Randomly generated)
        Bytes nonce; // 12-byte Base Nonce (Randomly generated)
        uint64_t file_size;
    };

    class FileEncryptor {
    public:
        FileEncryptor(const std::string& input_path);
        ~FileEncryptor();

        // Initialize: Generates random Key and Nonce
        std::expected<FileMetadata, FileError> init();

        // Get total number of chunks
        size_t get_total_chunks() const;

        // Read and Encrypt a specific chunk index
        // Returns: [Ciphertext + Tag] (Size <= ENCRYPTED_CHUNK_SIZE)
        std::expected<Bytes, FileError> get_encrypted_chunk(size_t chunk_index);

    private:
        std::filesystem::path path_;
        std::ifstream file_;
        uint64_t file_size_ = 0;

        Bytes key_;
        Bytes base_nonce_;
    };

    class FileDecryptor {
    public:
        // We need the key and base_nonce that were sent via the E2EE message
        FileDecryptor(const std::string& output_path, const Bytes& key, const Bytes& base_nonce);
        ~FileDecryptor();

        std::expected<void, FileError> init();

        // Decrypt and Write a specific chunk index
        // Input: [Ciphertext + Tag]
        std::expected<void, FileError> write_chunk(size_t chunk_index, const Bytes& encrypted_chunk);

    private:
        std::filesystem::path path_;
        std::ofstream file_;
        Bytes key_;
        Bytes base_nonce_;
    };

} // namespace nest::crypto