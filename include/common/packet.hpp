#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

namespace vpn {

// ── 消息类型 ──────────────────────────────────────────────────────────────
enum class MsgType : uint8_t {
    HANDSHAKE_INIT  = 0x01,
    HANDSHAKE_RESP  = 0x02,
    DATA            = 0x03,
    KEEPALIVE       = 0x04,
    DISCONNECT      = 0x05,
};

// ── 包头（固定 4 字节）────────────────────────────────────────────────────
#pragma pack(push, 1)
struct PacketHeader {
    MsgType  type;
    uint8_t  reserved[3] = {0, 0, 0};
};

// ── 握手 Init（Client → Server）─────────────────────────────────────────
// layout: PacketHeader | sender_pubkey[32] | nonce[12] | hmac[32]
struct HandshakeInit {
    PacketHeader header;
    uint8_t      sender_pubkey[32];   // X25519 ephemeral public key
    uint8_t      nonce[12];           // random nonce for HKDF salt
    uint8_t      hmac[32];            // HMAC-SHA256 over (pubkey+nonce) with PSK
};

// ── 握手 Response（Server → Client）────────────────────────────────────
struct HandshakeResp {
    PacketHeader header;
    uint32_t     session_id;          // assigned session id
    uint8_t      sender_pubkey[32];
    uint8_t      nonce[12];
    uint8_t      hmac[32];
};

// ── 数据包 ───────────────────────────────────────────────────────────────
// layout: PacketHeader | session_id[4] | seq[8] | ciphertext_len[4] | ciphertext[...] | tag[16]
struct DataPacketHeader {
    PacketHeader header;
    uint32_t     session_id;
    uint64_t     seq;                 // monotonic nonce counter
    uint32_t     ciphertext_len;
    // followed by: uint8_t ciphertext[ciphertext_len]  (includes 16-byte AEAD tag)
};
#pragma pack(pop)

// ── 序列化助手 ────────────────────────────────────────────────────────────
inline std::vector<uint8_t> serialize_handshake_init(const HandshakeInit& h) {
    std::vector<uint8_t> buf(sizeof(HandshakeInit));
    std::memcpy(buf.data(), &h, sizeof(HandshakeInit));
    return buf;
}

inline std::vector<uint8_t> serialize_handshake_resp(const HandshakeResp& h) {
    std::vector<uint8_t> buf(sizeof(HandshakeResp));
    std::memcpy(buf.data(), &h, sizeof(HandshakeResp));
    return buf;
}

inline std::vector<uint8_t> build_data_packet(
    uint32_t session_id,
    uint64_t seq,
    const std::vector<uint8_t>& ciphertext)
{
    DataPacketHeader hdr{};
    hdr.header.type      = MsgType::DATA;
    hdr.session_id       = session_id;
    hdr.seq              = seq;
    hdr.ciphertext_len   = static_cast<uint32_t>(ciphertext.size());

    std::vector<uint8_t> buf(sizeof(DataPacketHeader) + ciphertext.size());
    std::memcpy(buf.data(), &hdr, sizeof(DataPacketHeader));
    std::memcpy(buf.data() + sizeof(DataPacketHeader), ciphertext.data(), ciphertext.size());
    return buf;
}

} // namespace vpn
