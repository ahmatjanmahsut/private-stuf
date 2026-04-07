#pragma once
#ifdef _WIN32

#include "itun.hpp"
#include <windows.h>
#include <cstdint>

// WinTun 运行时函数指针类型（来自 wintun.h 简化版）
typedef void* WINTUN_ADAPTER_HANDLE;
typedef void* WINTUN_SESSION_HANDLE;

namespace vpn {

class WindowsTun : public ITunDevice {
public:
    WindowsTun()  = default;
    ~WindowsTun() override { close(); }

    bool open(const std::string& name,
              const std::string& address,
              const std::string& netmask,
              int mtu = 1420) override;

    ssize_t read(uint8_t* buf, size_t len) override;
    ssize_t write(const uint8_t* buf, size_t len) override;
    void    close() override;
    bool    is_open() const override { return session_ != nullptr; }
    const std::string& dev_name() const override { return name_; }

private:
    HMODULE               wintun_dll_ = nullptr;
    WINTUN_ADAPTER_HANDLE adapter_    = nullptr;
    WINTUN_SESSION_HANDLE session_    = nullptr;
    std::string           name_;

    bool load_wintun();
    void unload_wintun();

    // WinTun API 函数指针
    using FnCreateAdapter   = WINTUN_ADAPTER_HANDLE (*)(const WCHAR*, const WCHAR*, const GUID*);
    using FnOpenAdapter     = WINTUN_ADAPTER_HANDLE (*)(const WCHAR*);
    using FnCloseAdapter    = void (*)(WINTUN_ADAPTER_HANDLE);
    using FnDeleteAdapter   = BOOL (*)(WINTUN_ADAPTER_HANDLE);
    using FnStartSession    = WINTUN_SESSION_HANDLE (*)(WINTUN_ADAPTER_HANDLE, DWORD);
    using FnEndSession      = void (*)(WINTUN_SESSION_HANDLE);
    using FnAllocSendPacket = BYTE* (*)(WINTUN_SESSION_HANDLE, DWORD);
    using FnSendPacket      = void (*)(WINTUN_SESSION_HANDLE, const BYTE*);
    using FnReceivePacket   = BYTE* (*)(WINTUN_SESSION_HANDLE, DWORD*);
    using FnReleaseRecvPkt  = void (*)(WINTUN_SESSION_HANDLE, const BYTE*);

    FnCreateAdapter   pfn_create_adapter_   = nullptr;
    FnCloseAdapter    pfn_close_adapter_    = nullptr;
    FnDeleteAdapter   pfn_delete_adapter_   = nullptr;
    FnStartSession    pfn_start_session_    = nullptr;
    FnEndSession      pfn_end_session_      = nullptr;
    FnAllocSendPacket pfn_alloc_send_pkt_   = nullptr;
    FnSendPacket      pfn_send_packet_      = nullptr;
    FnReceivePacket   pfn_receive_packet_   = nullptr;
    FnReleaseRecvPkt  pfn_release_recv_pkt_ = nullptr;
};

} // namespace vpn

#endif // _WIN32
