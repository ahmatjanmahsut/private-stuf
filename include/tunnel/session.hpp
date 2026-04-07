#pragma once
#include "crypto/icrypto.hpp"
#include "obfuscate/iobfuscator.hpp"
#include <array>
#include <bitset>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace vpn {

// ── 防重放滑动窗口 ────────────────────────────────────────────────────────
struct ReplayWindow {
    static constexpr size_t WINDOW = 256;

    uint64_t           last_seq = 0;
    std::bitset<WINDOW> bitmap;

    // 检查并记录 seq；重复/过旧返回 false
    bool check_and_update(uint64_t seq);
};

// ── 会话对象 ──────────────────────────────────────────────────────────────
struct Session {
    uint32_t session_id = 0;
    bool     established = false;

    std::unique_ptr<ICrypto>    crypto;
    std::vector<std::shared_ptr<IObfuscator>> obfuscators; // 按顺序 obfuscate

    ReplayWindow replay_window;
    mutable std::mutex mutex;

    // 组合混淆链（发送）
    std::vector<uint8_t> apply_obfuscation(const std::vector<uint8_t>& data) const;
    // 逆序解混淆（接收）
    std::vector<uint8_t> remove_obfuscation(const std::vector<uint8_t>& data) const;

    // 加密并封装为 DataPacket
    std::vector<uint8_t> encrypt_and_pack(const uint8_t* plain, size_t len);
    // 解封并解密 DataPacket，返回明文；seq 写入 out_seq
    std::vector<uint8_t> unpack_and_decrypt(const uint8_t* pkt, size_t pkt_len);
};

} // namespace vpn
