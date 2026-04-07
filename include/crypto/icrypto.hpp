#pragma once
#include <cstdint>
#include <vector>

namespace vpn {

class ICrypto {
public:
    virtual ~ICrypto() = default;

    // ── 两步握手 ─────────────────────────────────────────────────────────────
    // 步骤1：仅返回本端公钥（构造时已生成密钥对），不做 ECDH
    virtual bool get_public_key(std::vector<uint8_t>& out_pubkey) = 0;

    // 步骤2：传入对端公钥，完成 ECDH + HKDF 推导会话密钥
    // salt: 握手 nonce，用于 HKDF
    virtual bool do_ecdh(
        const uint8_t* peer_pubkey, size_t peer_pubkey_len,
        const uint8_t* salt,        size_t salt_len) = 0;

    // 兼容旧接口（等价于 get_public_key + do_ecdh 合并）
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
