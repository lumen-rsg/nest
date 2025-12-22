//
// Created by cv2 on 23.12.2025.
//

#include "storage.hpp"
#include <openssl/sha.h>
#include <iostream>
#include <print>
#include <random>
#include <sstream>
#include <iomanip>

namespace nest {

StorageEngine::StorageEngine(const std::string& root_path)
    : root_(root_path) {
    temp_dir_ = root_ / "temp";
    final_dir_ = root_ / "store";
}

bool StorageEngine::init() {
    try {
        std::filesystem::create_directories(temp_dir_);
        std::filesystem::create_directories(final_dir_);
        return true;
    } catch (const std::exception& e) {
        std::println(stderr, "[Storage] Init failed: {}", e.what());
        return false;
    }
}

// Generate a random temp ID
std::expected<std::string, StorageError> StorageEngine::begin_upload() {
    // Generate UUID-like string
    std::random_device rd;
    std::stringstream ss;
    ss << std::hex << rd() << rd() << rd() << rd();
    return ss.str();
}

std::expected<void, StorageError> StorageEngine::append_chunk(const std::string& temp_id, const std::vector<uint8_t>& data) {
    // Sanity check temp_id to prevent traversal
    if (temp_id.find('/') != std::string::npos || temp_id.find('\\') != std::string::npos) {
        return std::unexpected(StorageError::AccessDenied);
    }

    auto path = temp_dir_ / temp_id;

    // Open in append binary mode
    std::ofstream ofs(path, std::ios::binary | std::ios::app);
    if (!ofs.is_open()) return std::unexpected(StorageError::IOError);

    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    if (!ofs) return std::unexpected(StorageError::IOError);

    // Check size limit (e.g., 100MB hard limit per file)
    if (std::filesystem::file_size(path) > 100 * 1024 * 1024) {
        std::filesystem::remove(path); // Delete partial
        return std::unexpected(StorageError::QuotaExceeded);
    }

    return {};
}

std::expected<std::string, StorageError> StorageEngine::finalize_upload(
    const std::string& temp_id,
    const std::string& uploader_pubkey_hex
) {
    if (temp_id.find('/') != std::string::npos) return std::unexpected(StorageError::AccessDenied);

    auto temp_path = temp_dir_ / temp_id;
    if (!std::filesystem::exists(temp_path)) return std::unexpected(StorageError::NotFound);

    // 1. Calculate Hash (SHA256) of the completed file
    std::string sha256_hex = calculate_file_hash(temp_path);
    if (sha256_hex.empty()) return std::unexpected(StorageError::IOError);

    // 2. Move to Final (CAS)
    // Structure: store/ab/abcdef123... (Sharding by first 2 chars to avoid huge dirs)
    std::string shard = sha256_hex.substr(0, 2);
    auto shard_dir = final_dir_ / shard;
    std::filesystem::create_directories(shard_dir);

    auto final_path = shard_dir / sha256_hex;

    // Atomic Move
    try {
        // If exists, we just overwrite (it's the same content anyway, CAS property)
        std::filesystem::rename(temp_path, final_path);
    } catch (...) {
        return std::unexpected(StorageError::IOError);
    }

    // 3. (Metadata would be updated in DB by the caller using sha256_hex)

    return sha256_hex;
}

std::expected<std::vector<uint8_t>, StorageError> StorageEngine::read_chunk(
    const std::string& file_hash,
    uint64_t offset,
    size_t length
) {
    if (!is_valid_hash(file_hash)) return std::unexpected(StorageError::InvalidHash);

    std::string shard = file_hash.substr(0, 2);
    auto path = final_dir_ / shard / file_hash;

    if (!std::filesystem::exists(path)) return std::unexpected(StorageError::NotFound);

    uint64_t file_size = std::filesystem::file_size(path);
    if (offset >= file_size) return std::unexpected(StorageError::IOError);

    // Clamp length
    if (offset + length > file_size) {
        length = file_size - offset;
    }

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) return std::unexpected(StorageError::IOError);

    ifs.seekg(offset);
    std::vector<uint8_t> buffer(length);
    ifs.read(reinterpret_cast<char*>(buffer.data()), length);

    if (!ifs) return std::unexpected(StorageError::IOError);

    return buffer;
}

bool StorageEngine::is_valid_hash(const std::string& hash) {
    if (hash.length() != 64) return false;
    // Check hex
    for (char c : hash) {
        if (!isxdigit(c)) return false;
    }
    return true;
}

std::string StorageEngine::calculate_file_hash(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    // Handle remaining bytes
    if (file.gcount() > 0) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

} // namespace nest