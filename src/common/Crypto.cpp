//
// Created by cv2 on 22.12.2025.
//

#include "Crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <print>
#include <memory>
#include <cstring>

namespace nest::crypto {

// Helper for smart pointers to OpenSSL objects
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

// --- Internal Helpers ---

// Extract raw bytes from an EVP_PKEY
static std::expected<KeyPair, Error> get_raw_keys(EVP_PKEY* pkey) {
    size_t pub_len = 0;
    size_t priv_len = 0;

    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &pub_len) <= 0) return std::unexpected(Error::KeyGenFailed);
    if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &priv_len) <= 0) return std::unexpected(Error::KeyGenFailed);

    Bytes pub(pub_len);
    Bytes priv(priv_len);

    EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pub_len);
    EVP_PKEY_get_raw_private_key(pkey, priv.data(), &priv_len);

    return KeyPair{pub, priv};
}

static EvpPkeyPtr load_key(int type, const Bytes& priv, const Bytes& pub) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(type, nullptr, priv.data(), priv.size());
    return EvpPkeyPtr(pkey, EVP_PKEY_free);
}

static EvpPkeyPtr load_pub_key(int type, const Bytes& pub) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(type, nullptr, pub.data(), pub.size());
    return EvpPkeyPtr(pkey, EVP_PKEY_free);
}

// --- Implementation ---

std::expected<KeyPair, Error> generate_identity_key() {
    // Generate Ed25519 (Signing)
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    if (!pkey) return std::unexpected(Error::KeyGenFailed);

    EvpPkeyPtr key_ptr(pkey, EVP_PKEY_free);
    return get_raw_keys(pkey);
}

std::expected<KeyPair, Error> generate_ephemeral_key() {
    // Generate X25519 (Key Exchange)
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    if (!pkey) return std::unexpected(Error::KeyGenFailed);

    EvpPkeyPtr key_ptr(pkey, EVP_PKEY_free);
    return get_raw_keys(pkey);
}

std::expected<Bytes, Error> sign(const Bytes& message, const Bytes& private_key) {
    auto key = load_key(EVP_PKEY_ED25519, private_key, {});
    if (!key) return std::unexpected(Error::InvalidKey);

    EvpMdCtxPtr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (EVP_DigestSignInit(md_ctx.get(), nullptr, nullptr, nullptr, key.get()) <= 0)
        return std::unexpected(Error::SigningFailed);

    size_t sig_len = 0;
    // Determine size
    if (EVP_DigestSign(md_ctx.get(), nullptr, &sig_len, message.data(), message.size()) <= 0)
         return std::unexpected(Error::SigningFailed);

    Bytes signature(sig_len);
    if (EVP_DigestSign(md_ctx.get(), signature.data(), &sig_len, message.data(), message.size()) <= 0)
         return std::unexpected(Error::SigningFailed);

    return signature;
}

bool verify(const Bytes& message, const Bytes& signature, const Bytes& public_key) {
    auto key = load_pub_key(EVP_PKEY_ED25519, public_key);
    if (!key) return false;

    EvpMdCtxPtr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, nullptr, nullptr, key.get()) <= 0) return false;

    return EVP_DigestVerify(md_ctx.get(), signature.data(), signature.size(), message.data(), message.size()) == 1;
}

std::expected<Bytes, Error> derive_secret(const Bytes& my_private, const Bytes& peer_public) {
    auto my_key = load_key(EVP_PKEY_X25519, my_private, {});
    auto peer_key = load_pub_key(EVP_PKEY_X25519, peer_public);
    if (!my_key || !peer_key) return std::unexpected(Error::InvalidKey);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(my_key.get(), nullptr);
    if (!ctx) return std::unexpected(Error::DerivationFailed);

    if (EVP_PKEY_derive_init(ctx) <= 0) return std::unexpected(Error::DerivationFailed);
    if (EVP_PKEY_derive_set_peer(ctx, peer_key.get()) <= 0) return std::unexpected(Error::DerivationFailed);

    size_t secret_len = 0;
    EVP_PKEY_derive(ctx, nullptr, &secret_len);

    Bytes secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0)
        return std::unexpected(Error::DerivationFailed);

    EVP_PKEY_CTX_free(ctx);
    return secret;
}

std::expected<Bytes, Error> encrypt_aes_gcm(const Bytes& plaintext, const Bytes& key) {
    if (key.size() != 32) return std::unexpected(Error::InvalidKey); // AES-256 needs 32 bytes

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::unexpected(Error::EncryptionFailed);

    // 1. Generate Nonce (IV) - 12 Bytes for GCM
    Bytes nonce(12);
    if (RAND_bytes(nonce.data(), 12) <= 0) return std::unexpected(Error::EncryptionFailed);

    // 2. Init Encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), nonce.data()) <= 0)
        return std::unexpected(Error::EncryptionFailed);

    // 3. Encrypt
    Bytes ciphertext(plaintext.size());
    int len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) <= 0)
        return std::unexpected(Error::EncryptionFailed);

    int ciphertext_len = len;

    // Finalize (GCM doesn't usually output bytes here but calling it checks integrity/padding logic if needed)
    if (EVP_EncryptFinal_ex(ctx, nullptr, &len) <= 0) return std::unexpected(Error::EncryptionFailed);

    // 4. Get Tag (16 Bytes)
    Bytes tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) <= 0)
        return std::unexpected(Error::EncryptionFailed);

    EVP_CIPHER_CTX_free(ctx);

    // 5. Pack: [Nonce (12)] + [Ciphertext] + [Tag (16)]
    Bytes result;
    result.reserve(12 + ciphertext_len + 16);
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());

    return result;
}

std::expected<Bytes, Error> decrypt_aes_gcm(const Bytes& payload, const Bytes& key) {
    if (key.size() != 32) return std::unexpected(Error::InvalidKey);
    if (payload.size() < 28) return std::unexpected(Error::DecryptionFailed); // 12 nonce + 16 tag

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::unexpected(Error::DecryptionFailed);

    // Unpack
    // [Nonce (12)] ... [Ciphertext] ... [Tag (16)]
    const uint8_t* nonce = payload.data();
    const uint8_t* ciphertext = payload.data() + 12;
    size_t ciphertext_len = payload.size() - 12 - 16;
    const uint8_t* tag = payload.data() + 12 + ciphertext_len;

    // Init Decrypt
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), nonce) <= 0)
        return std::unexpected(Error::DecryptionFailed);

    Bytes plaintext(ciphertext_len);
    int len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, static_cast<int>(ciphertext_len)) <= 0)
        return std::unexpected(Error::DecryptionFailed);

    // Set Tag for verification
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) <= 0)
        return std::unexpected(Error::DecryptionFailed);

    // Finalize checks the tag
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) return std::unexpected(Error::DecryptionFailed); // Tag mismatch!

    return plaintext;
}

    std::expected<Bytes, Error> derive_key_from_password(
    const std::string& password,
    const Bytes& salt,
    int iterations
) {
    Bytes key(32); // 256-bit key

    // PKCS5_PBKDF2_HMAC is the standard OpenSSL function
    int res = PKCS5_PBKDF2_HMAC(
        password.c_str(), static_cast<int>(password.length()),
        salt.data(), static_cast<int>(salt.size()),
        iterations,
        EVP_sha256(),
        static_cast<int>(key.size()),
        key.data()
    );

    if (res != 1) return std::unexpected(Error::DerivationFailed);
    return key;
}

} // namespace nest::crypto