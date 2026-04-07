#include "tunnel/session.hpp"
#include "common/packet.hpp"
#include "common/logger.hpp"
#include <cstring>
#include <stdexcept>

namespace vpn {

// ── ReplayWindow ─────────────────────────────────────────────────────────
bool ReplayWindow::check_and_update(uint64_t seq) {
    if (seq == 0 && last_seq == 0 && !bitmap.test(0)) {
        // first packet
        bitmap.set(0);
        return true;
    }
    if (seq + WINDOW <= last_seq) {
        // too old
        return false;
    }
    if (seq > last_seq) {
        // advance window
        uint64_t advance = seq - last_seq;
        if (advance >= WINDOW) bitmap.reset();
        else {
            // shift bitmap left by advance
            bitmap <<= static_cast<int>(advance);
        }
        last_seq = seq;
        bitmap.set(seq % WINDOW);
        return true;
    }
    // within window
    size_t bit = static_cast<size_t>(seq % WINDOW);
    if (bitmap.test(bit)) return false; // duplicate
    bitmap.set(bit);
    return true;
}

// ── Session obfuscation helpers ───────────────────────────────────────────
std::vector<uint8_t> Session::apply_obfuscation(const std::vector<uint8_t>& data) const {
    std::vector<uint8_t> out = data;
    for (auto& obf : obfuscators)
        out = obf->obfuscate(out);
    return out;
}

std::vector<uint8_t> Session::remove_obfuscation(const std::vector<uint8_t>& data) const {
    std::vector<uint8_t> out = data;
    for (auto it = obfuscators.rbegin(); it != obfuscators.rend(); ++it)
        out = (*it)->deobfuscate(out);
    return out;
}

// ── Session encrypt_and_pack ──────────────────────────────────────────────
std::vector<uint8_t> Session::encrypt_and_pack(const uint8_t* plain, size_t len) {
    std::lock_guard<std::mutex> lk(mutex);

    std::vector<uint8_t> ciphertext;
    if (!crypto->encrypt(plain, len, ciphertext)) {
        VPN_ERROR("Session {}: encrypt failed", session_id);
        return {};
    }

    uint64_t seq = crypto->send_counter() - 1; // counter was incremented inside encrypt
    auto pkt = build_data_packet(session_id, seq, ciphertext);
    return apply_obfuscation(pkt);
}

// ── Session unpack_and_decrypt ────────────────────────────────────────────
std::vector<uint8_t> Session::unpack_and_decrypt(const uint8_t* pkt, size_t pkt_len) {
    std::lock_guard<std::mutex> lk(mutex);

    // 去混淆
    std::vector<uint8_t> raw(pkt, pkt + pkt_len);
    raw = remove_obfuscation(raw);

    if (raw.size() < sizeof(DataPacketHeader)) {
        VPN_WARN("Session {}: packet too short after deobfuscate", session_id);
        return {};
    }

    DataPacketHeader hdr{};
    std::memcpy(&hdr, raw.data(), sizeof(DataPacketHeader));

    if (hdr.header.type != MsgType::DATA) {
        VPN_WARN("Session {}: unexpected msg type", session_id);
        return {};
    }

    // 防重放检查
    if (!replay_window.check_and_update(hdr.seq)) {
        VPN_WARN("Session {}: replay detected seq={}", session_id, hdr.seq);
        return {};
    }

    size_t ct_offset = sizeof(DataPacketHeader);
    size_t ct_len    = hdr.ciphertext_len;
    if (raw.size() < ct_offset + ct_len) return {};

    std::vector<uint8_t> plaintext;
    if (!crypto->decrypt(raw.data() + ct_offset, ct_len, hdr.seq, plaintext)) {
        VPN_ERROR("Session {}: decrypt failed seq={}", session_id, hdr.seq);
        return {};
    }

    return plaintext;
}

} // namespace vpn
