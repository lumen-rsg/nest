//
// Created by cv2 on 23.12.2025.
//

#include "file_crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <print>

namespace nest::crypto {

// Helper: Increment the 12-byte nonce by the chunk index (Big Endian arithmetic)
static Bytes calculate_nonce(const Bytes& base, size_t index) {
    Bytes nonce = base; // Copy base (12 bytes)

    // Treat the last 4 bytes as a counter for simplicity (supports 4 billion chunks = ~256TB file)
    // We add 'index' to the last 4 bytes in Big Endian order.
    uint32_t val = 0;
    // Extract last 4 bytes
    for (int i = 0; i < 4; i++) val = (val << 8) | nonce[8 + i];

    val += static_cast<uint32_t>(index);

    // Put back
    for (int i = 3; i >= 0; i--) {
        nonce[8 + i] = (val & 0xFF);
        val >>= 8;
    }
    return nonce;
}

// --- FileEncryptor ---

FileEncryptor::FileEncryptor(const std::string& input_path) : path_(input_path) {}

FileEncryptor::~FileEncryptor() {
    if (file_.is_open()) file_.close();
}

std::expected<FileMetadata, FileError> FileEncryptor::init() {
    if (!std::filesystem::exists(path_)) return std::unexpected(FileError::OpenFailed);
    file_size_ = std::filesystem::file_size(path_);

    file_.open(path_, std::ios::binary);
    if (!file_.is_open()) return std::unexpected(FileError::OpenFailed);

    // Generate random crypto material
    key_.resize(32);
    base_nonce_.resize(12);

    if (RAND_bytes(key_.data(), 32) <= 0) return std::unexpected(FileError::CryptoFailed);
    if (RAND_bytes(base_nonce_.data(), 12) <= 0) return std::unexpected(FileError::CryptoFailed);

    return FileMetadata{key_, base_nonce_, file_size_};
}

size_t FileEncryptor::get_total_chunks() const {
    if (file_size_ == 0) return 0;
    return (file_size_ + FILE_CHUNK_SIZE - 1) / FILE_CHUNK_SIZE;
}

std::expected<Bytes, FileError> FileEncryptor::get_encrypted_chunk(size_t chunk_index) {
    if (!file_.is_open()) return std::unexpected(FileError::OpenFailed);

    // 1. Seek to chunk position
    uint64_t offset = chunk_index * FILE_CHUNK_SIZE;
    if (offset >= file_size_) return std::unexpected(FileError::InvalidSize);

    file_.clear(); // Clear EOF flags
    file_.seekg(offset);

    // 2. Read Plaintext
    size_t to_read = std::min(FILE_CHUNK_SIZE, static_cast<size_t>(file_size_ - offset));
    Bytes buffer(to_read);
    file_.read(reinterpret_cast<char*>(buffer.data()), to_read);
    if (file_.gcount() != static_cast<std::streamsize>(to_read)) return std::unexpected(FileError::ReadFailed);

    // 3. Encrypt (AES-GCM)
    Bytes chunk_nonce = calculate_nonce(base_nonce_, chunk_index);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::unexpected(FileError::CryptoFailed);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key_.data(), chunk_nonce.data()) <= 0) {
        EVP_CIPHER_CTX_free(ctx); return std::unexpected(FileError::CryptoFailed);
    }

    Bytes ciphertext(to_read);
    int len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, buffer.data(), static_cast<int>(to_read)) <= 0) {
        EVP_CIPHER_CTX_free(ctx); return std::unexpected(FileError::CryptoFailed);
    }

    int final_len = 0;
    EVP_EncryptFinal_ex(ctx, nullptr, &final_len); // GCM doesn't output here usually

    // Get Tag
    Bytes tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    // 4. Combine [Ciphertext + Tag]
    Bytes result;
    result.reserve(ciphertext.size() + tag.size());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());

    return result;
}

// --- FileDecryptor ---

FileDecryptor::FileDecryptor(const std::string& output_path, const Bytes& key, const Bytes& base_nonce)
    : path_(output_path), key_(key), base_nonce_(base_nonce) {}

FileDecryptor::~FileDecryptor() {
    if (file_.is_open()) file_.close();
}

std::expected<void, FileError> FileDecryptor::init() {
    // Open for writing (binary)
    file_.open(path_, std::ios::binary | std::ios::out);
    if (!file_.is_open()) return std::unexpected(FileError::OpenFailed);
    return {};
}

std::expected<void, FileError> FileDecryptor::write_chunk(size_t chunk_index, const Bytes& encrypted_chunk) {
    if (!file_.is_open()) return std::unexpected(FileError::OpenFailed);
    if (encrypted_chunk.size() <= GCM_TAG_SIZE) return std::unexpected(FileError::InvalidSize);

    // 1. Separate Ciphertext and Tag
    // Format: [Ciphertext .... ][Tag (16 bytes)]
    size_t cipher_len = encrypted_chunk.size() - GCM_TAG_SIZE;
    const uint8_t* cipher_ptr = encrypted_chunk.data();
    const uint8_t* tag_ptr = encrypted_chunk.data() + cipher_len;

    // 2. Decrypt
    Bytes chunk_nonce = calculate_nonce(base_nonce_, chunk_index);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::unexpected(FileError::CryptoFailed);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key_.data(), chunk_nonce.data()) <= 0) {
        EVP_CIPHER_CTX_free(ctx); return std::unexpected(FileError::CryptoFailed);
    }

    Bytes plaintext(cipher_len);
    int len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, cipher_ptr, static_cast<int>(cipher_len)) <= 0) {
        EVP_CIPHER_CTX_free(ctx); return std::unexpected(FileError::CryptoFailed);
    }

    // Set Tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag_ptr);

    // Finalize (Checks Tag)
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        // AUTHENTICATION FAILED - Chunk is corrupted or tampered!
        return std::unexpected(FileError::CryptoFailed);
    }

    // 3. Write to Disk
    // Seek to correct offset to allow out-of-order writes
    uint64_t offset = chunk_index * FILE_CHUNK_SIZE;
    file_.seekp(offset);
    file_.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());

    if (!file_) return std::unexpected(FileError::WriteFailed);

    return {};
}

} // namespace nest::crypto