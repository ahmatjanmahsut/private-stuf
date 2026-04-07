#include "crypto/aes_gcm_crypto.hpp"
#include "common/logger.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <cstring>
#include <stdexcept>

namespace vpn {

// ─── 复用与 chacha20 相同的 X25519/HKDF 工具函数 ─────────────────────────
static bool x25519_keygen_aes(uint8_t priv[32], uint8_t pub[32]) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) return false;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    if (!pkey) return false;
    size_t len = 32;
    EVP_PKEY_get_raw_private_key(pkey, priv, &len);
    len = 32;
    EVP_PKEY_get_raw_public_key(pkey, pub, &len);
    EVP_PKEY_free(pkey);
    return true;
}

static bool x25519_ecdh_aes(const uint8_t priv[32], const uint8_t peer_pub[32],
                              uint8_t shared[32]) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv, 32);
    EVP_PKEY* ppub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub, 32);
    if (!pkey || !ppub) { EVP_PKEY_free(pkey); EVP_PKEY_free(ppub); return false; }
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    size_t len = 32;
    bool ok = (EVP_PKEY_derive_init(ctx) > 0 &&
               EVP_PKEY_derive_set_peer(ctx, ppub) > 0 &&
               EVP_PKEY_derive(ctx, shared, &len) > 0);
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey); EVP_PKEY_free(ppub);
    return ok;
}

static bool hkdf_sha256_aes(const uint8_t* ikm, size_t ikm_len,
                              const uint8_t* salt, size_t salt_len,
                              const char* info,
                              uint8_t* out, size_t out_len) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) return false;
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    OSSL_PARAM params[5];
    int idx = 0;
    params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                        const_cast<char*>("SHA256"), 0);
    params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                        const_cast<uint8_t*>(ikm), ikm_len);
    if (salt && salt_len)
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                            const_cast<uint8_t*>(salt), salt_len);
    if (info)
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                            const_cast<char*>(info), strlen(info));
    params[idx] = OSSL_PARAM_construct_end();
    bool ok = (EVP_KDF_derive(kctx, out, out_len, params) > 0);
    EVP_KDF_CTX_free(kctx);
    return ok;
}

// ─── AesGcmCrypto ──────────────────────────────────────────────────────
AesGcmCrypto::AesGcmCrypto() {
    uint8_t pub[32];
    if (!x25519_keygen_aes(private_key_.data(), pub))
        throw std::runtime_error("X25519 keygen failed (AES-GCM)");
}

AesGcmCrypto::~AesGcmCrypto() {
    OPENSSL_cleanse(private_key_.data(), 32);
    OPENSSL_cleanse(session_key_.data(), 32);
}

bool AesGcmCrypto::handshake(const uint8_t* peer_pubkey, size_t,
                               const uint8_t* salt, size_t salt_len,
                               std::vector<uint8_t>& out_pubkey) {
    uint8_t pub[32];
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                   private_key_.data(), 32);
    if (!pkey) return false;
    size_t len = 32;
    EVP_PKEY_get_raw_public_key(pkey, pub, &len);
    EVP_PKEY_free(pkey);
    out_pubkey.assign(pub, pub + 32);

    uint8_t shared[32];
    if (!x25519_ecdh_aes(private_key_.data(), peer_pubkey, shared)) return false;
    if (!derive_session_key(shared, salt, salt_len)) return false;
    OPENSSL_cleanse(shared, 32);

    key_ready_  = true;
    send_nonce_ = 0;
    return true;
}

bool AesGcmCrypto::derive_session_key(const uint8_t* shared, const uint8_t* salt, size_t salt_len) {
    return hkdf_sha256_aes(shared, 32, salt, salt_len, "vpntunnel-aesgcm",
                            session_key_.data(), 32);
}

std::array<uint8_t, 12> AesGcmCrypto::make_nonce(uint64_t counter) {
    std::array<uint8_t, 12> n{};
    for (int i = 0; i < 8; ++i)
        n[i] = static_cast<uint8_t>((counter >> (8 * i)) & 0xff);
    return n;
}

bool AesGcmCrypto::encrypt(const uint8_t* plain, size_t plain_len,
                             std::vector<uint8_t>& ciphertext) {
    if (!key_ready_) return false;
    uint64_t nonce_val = send_nonce_.fetch_add(1);
    auto nonce = make_nonce(nonce_val);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    ciphertext.resize(plain_len + 16);
    int outl = 0, finl = 0;
    bool ok =
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) > 0 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) > 0 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, session_key_.data(), nonce.data()) > 0 &&
        EVP_EncryptUpdate(ctx, ciphertext.data(), &outl,
                          plain, static_cast<int>(plain_len)) > 0 &&
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + outl, &finl) > 0;

    if (ok) {
        uint8_t tag[16];
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) > 0;
        if (ok)
            std::memcpy(ciphertext.data() + outl + finl, tag, 16);
    }

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) ciphertext.clear();
    return ok;
}

bool AesGcmCrypto::decrypt(const uint8_t* cipher, size_t cipher_len,
                             uint64_t seq,
                             std::vector<uint8_t>& plaintext) {
    if (!key_ready_ || cipher_len < 16) return false;
    auto nonce  = make_nonce(seq);
    size_t ct_len = cipher_len - 16;
    const uint8_t* tag = cipher + ct_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    plaintext.resize(ct_len);
    int outl = 0, finl = 0;
    bool ok =
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) > 0 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) > 0 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, session_key_.data(), nonce.data()) > 0 &&
        EVP_DecryptUpdate(ctx, plaintext.data(), &outl,
                          cipher, static_cast<int>(ct_len)) > 0 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                             const_cast<uint8_t*>(tag)) > 0 &&
        EVP_DecryptFinal_ex(ctx, plaintext.data() + outl, &finl) > 0;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) plaintext.clear();
    return ok;
}

} // namespace vpn
