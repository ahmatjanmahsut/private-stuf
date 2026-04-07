#include "tun/windows_tun.hpp"
#ifdef _WIN32

#include "common/logger.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdexcept>

#pragma comment(lib, "iphlpapi.lib")

namespace vpn {

bool WindowsTun::load_wintun() {
    wintun_dll_ = LoadLibraryW(L"wintun.dll");
    if (!wintun_dll_) {
        VPN_ERROR("Failed to load wintun.dll – ensure it is in PATH or executable directory");
        return false;
    }

#define LOAD_FN(var, type, name) \
    var = reinterpret_cast<type>(GetProcAddress(wintun_dll_, name)); \
    if (!var) { VPN_ERROR("wintun.dll missing: {}", name); unload_wintun(); return false; }

    LOAD_FN(pfn_create_adapter_,   FnCreateAdapter,   "WintunCreateAdapter")
    LOAD_FN(pfn_close_adapter_,    FnCloseAdapter,    "WintunCloseAdapter")
    LOAD_FN(pfn_delete_adapter_,   FnDeleteAdapter,   "WintunDeleteAdapter")
    LOAD_FN(pfn_start_session_,    FnStartSession,    "WintunStartSession")
    LOAD_FN(pfn_end_session_,      FnEndSession,      "WintunEndSession")
    LOAD_FN(pfn_alloc_send_pkt_,   FnAllocSendPacket, "WintunAllocateSendPacket")
    LOAD_FN(pfn_send_packet_,      FnSendPacket,      "WintunSendPacket")
    LOAD_FN(pfn_receive_packet_,   FnReceivePacket,   "WintunReceivePacket")
    LOAD_FN(pfn_release_recv_pkt_, FnReleaseRecvPkt,  "WintunReleaseReceivePacket")
#undef LOAD_FN
    return true;
}

void WindowsTun::unload_wintun() {
    if (wintun_dll_) { FreeLibrary(wintun_dll_); wintun_dll_ = nullptr; }
}

bool WindowsTun::open(const std::string& name,
                       const std::string& address,
                       const std::string& /*netmask*/,
                       int /*mtu*/) {
    if (!load_wintun()) return false;

    // Convert name to wide string
    std::wstring wname(name.begin(), name.end());
    // Use a fixed GUID for the adapter so recreation is idempotent
    GUID guid = {0x1a2b3c4d, 0x5e6f, 0x7a8b, {0x9c,0xad,0xbe,0xcf,0xd0,0xe1,0xf2,0x03}};

    adapter_ = pfn_create_adapter_(wname.c_str(), L"VpnTunnel", &guid);
    if (!adapter_) {
        VPN_ERROR("WintunCreateAdapter failed");
        unload_wintun();
        return false;
    }

    // Set IPv4 address via MIB_UNICASTIPADDRESS_ROW (simplified – use netsh as fallback)
    // For simplicity we call netsh here; in production use SetUnicastIpAddressEntry
    std::string cmd = "netsh interface ip set address \"" + name
                      + "\" static " + address + " 255.255.255.0";
    system(cmd.c_str());

    session_ = pfn_start_session_(adapter_, 0x400000 /*4 MB ring*/);
    if (!session_) {
        VPN_ERROR("WintunStartSession failed");
        pfn_close_adapter_(adapter_); adapter_ = nullptr;
        unload_wintun();
        return false;
    }

    name_ = name;
    VPN_INFO("WinTun adapter {} started", name_);
    return true;
}

ssize_t WindowsTun::read(uint8_t* buf, size_t len) {
    if (!session_) return -1;
    DWORD pkt_size = 0;
    BYTE* pkt = pfn_receive_packet_(session_, &pkt_size);
    if (!pkt) return 0; // no packet available (non-blocking)
    size_t copy_len = (pkt_size < len) ? pkt_size : len;
    memcpy(buf, pkt, copy_len);
    pfn_release_recv_pkt_(session_, pkt);
    return static_cast<ssize_t>(copy_len);
}

ssize_t WindowsTun::write(const uint8_t* buf, size_t len) {
    if (!session_) return -1;
    BYTE* pkt = pfn_alloc_send_pkt_(session_, static_cast<DWORD>(len));
    if (!pkt) return -1;
    memcpy(pkt, buf, len);
    pfn_send_packet_(session_, pkt);
    return static_cast<ssize_t>(len);
}

void WindowsTun::close() {
    if (session_) {
        pfn_end_session_(session_);
        session_ = nullptr;
    }
    if (adapter_) {
        pfn_close_adapter_(adapter_);
        adapter_ = nullptr;
    }
    unload_wintun();
    VPN_INFO("WinTun adapter {} closed", name_);
}

} // namespace vpn

#endif // _WIN32
