#pragma once
#include <cstdint>
#include <vector>

namespace vpn {

class ICrypto {
public:
    virtual ~ICrypto() = default;

    // 生成本端临时密钥对，返回公钥；传入对端公钥，推导会话密钥
    // salt: 握手 nonce，用于 HKDF
    virtual bool handshake(
        const uint8_t* peer_pubkey, size_t peer_pubkey_len,
        const uint8_t* salt,        size_t salt_len,
        std::vector<uint8_t>& out_pubkey) = 0;

    // 加密（nonce 计数器由实现内部递增）
    // 输出包含：ciphertext + 16-byte AEAD tag
    virtual bool encrypt(
        const uint8_t* plain, size_t plain_len,
        std::vector<uint8_t>& ciphertext) = 0;

    // 解密（seq 为预期 nonce，用于防重放验证）
    virtual bool decrypt(
        const uint8_t* cipher, size_t cipher_len,
        uint64_t seq,
        std::vector<uint8_t>& plaintext) = 0;

    // 返回当前发包 nonce 计数器值
    virtual uint64_t send_counter() const = 0;

    // 算法名称（用于日志）
    virtual const char* name() const = 0;
};

} // namespace vpn
