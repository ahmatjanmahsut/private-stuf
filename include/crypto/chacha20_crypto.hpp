#pragma once
#include "icrypto.hpp"
#include <array>
#include <atomic>

namespace vpn {

class ChaCha20Crypto : public ICrypto {
public:
    ChaCha20Crypto();
    ~ChaCha20Crypto() override;

    bool handshake(
        const uint8_t* peer_pubkey, size_t peer_pubkey_len,
        const uint8_t* salt,        size_t salt_len,
        std::vector<uint8_t>& out_pubkey) override;

    bool encrypt(
        const uint8_t* plain, size_t plain_len,
        std::vector<uint8_t>& ciphertext) override;

    bool decrypt(
        const uint8_t* cipher, size_t cipher_len,
        uint64_t seq,
        std::vector<uint8_t>& plaintext) override;

    uint64_t send_counter() const override { return send_nonce_.load(); }
    const char* name() const override { return "ChaCha20-Poly1305"; }

private:
    // X25519 private key (32 bytes)
    std::array<uint8_t, 32> private_key_{};
    // Derived session key (32 bytes)
    std::array<uint8_t, 32> session_key_{};
    bool key_ready_ = false;

    std::atomic<uint64_t> send_nonce_{0};

    // Build 12-byte nonce from 64-bit counter
    static std::array<uint8_t, 12> make_nonce(uint64_t counter);
    bool derive_session_key(const uint8_t* shared_secret, const uint8_t* salt, size_t salt_len);
};

} // namespace vpn
