//
// Created by cv2 on 22.12.2025.
//

#pragma once
#include <vector>
#include <string>
#include <expected> // C++23
#include <openssl/evp.h>

namespace nest::crypto {

    using Bytes = std::vector<uint8_t>;

    enum class Error {
        KeyGenFailed,
        EncryptionFailed,
        DecryptionFailed,
        SigningFailed,
        VerificationFailed,
        DerivationFailed,
        InvalidKey
    };

    // --- Identity (Ed25519) ---
    struct KeyPair {
        Bytes public_key;
        Bytes private_key;
    };

    // Generate a long-term Identity Key (Ed25519)
    std::expected<KeyPair, Error> generate_identity_key();

    // Sign data with Private Identity Key
    std::expected<Bytes, Error> sign(const Bytes& message, const Bytes& private_key);

    // Verify signature with Public Identity Key
    bool verify(const Bytes& message, const Bytes& signature, const Bytes& public_key);


    // --- Encryption (X25519 + AES-GCM) ---

    // Generate an ephemeral keypair for ECDH (X25519)
    std::expected<KeyPair, Error> generate_ephemeral_key();

    // Derive a Shared Secret using my Private Key + Peer's Public Key
    // Returns 32 bytes of raw secret
    std::expected<Bytes, Error> derive_secret(const Bytes& my_private, const Bytes& peer_public);

    // AES-256-GCM Encrypt
    // Returns: [Nonce (12b) + Ciphertext + Tag (16b)] packed together
    std::expected<Bytes, Error> encrypt_aes_gcm(const Bytes& plaintext, const Bytes& key);

    // AES-256-GCM Decrypt
    // Input: [Nonce (12b) + Ciphertext + Tag (16b)]
    std::expected<Bytes, Error> decrypt_aes_gcm(const Bytes& payload, const Bytes& key);

    // Derive a Master Key from a password and salt using PBKDF2
    // iterations should be high (e.g. 600,000)
    std::expected<Bytes, Error> derive_key_from_password(
        const std::string& password,
        const Bytes& salt,
        int iterations = 600'000
    );

    std::string base64_encode(const unsigned char* data, size_t input_length);

} // namespace nest::crypto