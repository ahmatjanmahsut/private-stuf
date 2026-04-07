#include "web/web_ui.hpp"
#include "common/config.hpp"
#include "common/logger.hpp"
#ifdef VPN_SERVER_BUILD
#include "server/server.hpp"
#endif
#ifdef VPN_CLIENT_BUILD
#include "client/client.hpp"
#endif
#include <asio.hpp>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iomanip>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>

#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace vpn {
namespace {

using tcp = asio::ip::tcp;

#ifdef VPN_SERVER_BUILD
static constexpr const char* kRoleName = "server";
static constexpr const char* kRoleTitle = "VPN Tunnel Server";
#elif defined(VPN_CLIENT_BUILD)
static constexpr const char* kRoleName = "client";
static constexpr const char* kRoleTitle = "VPN Tunnel Client";
#else
#error "Web UI build requires VPN_SERVER_BUILD or VPN_CLIENT_BUILD"
#endif

std::string trim_copy(std::string s) {
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || std::isspace(static_cast<unsigned char>(s.back())))) {
        s.pop_back();
    }
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    return s.substr(start);
}

std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return s;
}

std::string html_escape(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (char ch : value) {
        switch (ch) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '\"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out.push_back(ch); break;
        }
    }
    return out;
}

std::string json_escape(const std::string& value) {
    std::ostringstream out;
    for (unsigned char ch : value) {
        switch (ch) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (ch < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(ch) << std::dec;
                } else {
                    out << static_cast<char>(ch);
                }
                break;
        }
    }
    return out.str();
}

std::string url_decode(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        const char ch = value[i];
        if (ch == '+') {
            out.push_back(' ');
            continue;
        }
        if (ch == '%' && i + 2 < value.size()) {
            const auto hex = value.substr(i + 1, 2);
            char* end = nullptr;
            const long decoded = std::strtol(hex.c_str(), &end, 16);
            if (end && *end == '\0') {
                out.push_back(static_cast<char>(decoded));
                i += 2;
                continue;
            }
        }
        out.push_back(ch);
    }
    return out;
}

std::map<std::string, std::string> parse_form_urlencoded(const std::string& body) {
    std::map<std::string, std::string> values;
    size_t start = 0;
    while (start <= body.size()) {
        size_t end = body.find('&', start);
        if (end == std::string::npos) {
            end = body.size();
        }
        const auto part = body.substr(start, end - start);
        const auto eq = part.find('=');
        const auto key = url_decode(part.substr(0, eq));
        const auto val = eq == std::string::npos ? std::string() : url_decode(part.substr(eq + 1));
        if (!key.empty()) {
            values[key] = val;
        }
        if (end == body.size()) {
            break;
        }
        start = end + 1;
    }
    return values;
}

bool form_has_checkbox(const std::map<std::string, std::string>& values, const std::string& key) {
    return values.find(key) != values.end();
}

int parse_int_or_default(const std::map<std::string, std::string>& values,
                         const std::string& key,
                         int current,
                         int min_value,
                         int max_value,
                         std::string& error) {
    const auto it = values.find(key);
    if (it == values.end() || it->second.empty()) {
        return current;
    }
    try {
        const int parsed = std::stoi(it->second);
        if (parsed < min_value || parsed > max_value) {
            error = "字段 " + key + " 超出允许范围";
            return current;
        }
        return parsed;
    } catch (...) {
        error = "字段 " + key + " 不是合法整数";
        return current;
    }
}

std::string form_value_or_default(const std::map<std::string, std::string>& values,
                                  const std::string& key,
                                  const std::string& current) {
    const auto it = values.find(key);
    if (it == values.end()) {
        return current;
    }
    return it->second;
}

CipherType parse_cipher_name(const std::string& value) {
    return value == "aes-256-gcm" ? CipherType::AES_256_GCM : CipherType::CHACHA20_POLY1305;
}

ObfuscateMode parse_obfuscation_name(const std::string& value) {
    const auto lower = lower_copy(value);
    if (lower == "http") {
        return ObfuscateMode::HTTP;
    }
    if (lower == "websocket") {
        return ObfuscateMode::WEBSOCKET;
    }
    if (lower == "padding") {
        return ObfuscateMode::PADDING;
    }
    return ObfuscateMode::NONE;
}

std::string obfuscation_slot_value(const std::vector<ObfuscateMode>& chain, size_t index) {
    if (index >= chain.size()) {
        return "none";
    }
    return to_string(chain[index]);
}

std::string checked_attr(bool enabled) {
    return enabled ? " checked" : "";
}

std::string selected_attr(const std::string& current, const std::string& expected) {
    return current == expected ? " selected" : "";
}

struct Notice {
    bool ok = true;
    std::string text;
};

struct RuntimeStatus {
    bool running = false;
    size_t session_count = 0;
    std::string message = "未启动";
    std::string config_path;
};

class IManagedRuntime {
public:
    virtual ~IManagedRuntime() = default;
    virtual void run() = 0;
    virtual void stop() = 0;
    virtual size_t session_count() const = 0;
};

#ifdef VPN_SERVER_BUILD
class ManagedRuntime final : public IManagedRuntime {
public:
    explicit ManagedRuntime(const Config& cfg)
        : cfg_(cfg), server_(cfg_) {}

    void run() override { server_.run(); }
    void stop() override { server_.stop(); }
    size_t session_count() const override { return server_.session_count(); }

private:
    Config cfg_;
    Server server_;
};
#endif

#ifdef VPN_CLIENT_BUILD
class ManagedRuntime final : public IManagedRuntime {
public:
    explicit ManagedRuntime(const Config& cfg)
        : cfg_(cfg), client_(cfg_) {}

    void run() override { client_.run(); }
    void stop() override { client_.stop(); }
    size_t session_count() const override { return client_.session_count(); }

private:
    Config cfg_;
    Client client_;
};
#endif

class RuntimeController {
public:
    explicit RuntimeController(std::string config_path)
        : config_path_(std::move(config_path)), cfg_(default_config()) {
        std::string ignored;
        reload_from_disk(ignored);
    }

    ~RuntimeController() {
        std::string ignored;
        stop(ignored);
        if (runtime_thread_.joinable()) {
            runtime_thread_.join();
        }
    }

    std::string role_name() const { return kRoleName; }

    Config current_config() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cfg_;
    }

    void set_config(const Config& cfg) {
        std::lock_guard<std::mutex> lock(mutex_);
        cfg_ = cfg;
        cfg_.is_server = std::string(kRoleName) == "server";
    }

    bool reload_from_disk(std::string& message) {
        try {
            Config cfg = Config::load_from_file(config_path_);
            cfg.is_server = std::string(kRoleName) == "server";
            {
                std::lock_guard<std::mutex> lock(mutex_);
                cfg_ = cfg;
            }
            Logger::set_level(cfg.log_level);
            message = "已从磁盘重新加载配置";
            return true;
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(mutex_);
            cfg_ = default_config();
            message = std::string("加载配置失败，已回退默认值: ") + e.what();
            return false;
        }
    }

    bool save_to_disk(std::string& message) {
        try {
            Config snapshot = current_config();
            snapshot.save_to_file(config_path_);
            message = running_.load()
                ? "配置已保存。若已修改隧道参数，请点击“重启隧道”应用变更。"
                : "配置已保存到磁盘";
            return true;
        } catch (const std::exception& e) {
            message = std::string("保存配置失败: ") + e.what();
            return false;
        }
    }

    bool apply_form(const std::map<std::string, std::string>& form, std::string& message) {
        Config updated = current_config();
        std::string error;

        updated.is_server = std::string(kRoleName) == "server";
        updated.cipher = parse_cipher_name(form_value_or_default(form, "cipher", to_string(updated.cipher)));
        updated.psk = form_value_or_default(form, "psk", updated.psk);

        updated.tun.name = form_value_or_default(form, "tun_name", updated.tun.name);
        updated.tun.address = form_value_or_default(form, "tun_address", updated.tun.address);
        updated.tun.netmask = form_value_or_default(form, "tun_netmask", updated.tun.netmask);
        updated.tun.mtu = parse_int_or_default(form, "tun_mtu", updated.tun.mtu, 576, 9000, error);
        if (!error.empty()) { message = error; return false; }

#ifdef VPN_SERVER_BUILD
        updated.listen_host = form_value_or_default(form, "listen_host", updated.listen_host);
        updated.listen_port = static_cast<uint16_t>(parse_int_or_default(form, "listen_port", updated.listen_port, 1, 65535, error));
        if (!error.empty()) { message = error; return false; }
#endif
#ifdef VPN_CLIENT_BUILD
        updated.peer_host = form_value_or_default(form, "peer_host", updated.peer_host);
        updated.peer_port = static_cast<uint16_t>(parse_int_or_default(form, "peer_port", updated.peer_port, 1, 65535, error));
        if (!error.empty()) { message = error; return false; }
#endif

        updated.log_level = parse_int_or_default(form, "log_level", updated.log_level, 0, 3, error);
        if (!error.empty()) { message = error; return false; }
        updated.handshake_timeout = parse_int_or_default(form, "handshake_timeout", updated.handshake_timeout, 1, 120, error);
        if (!error.empty()) { message = error; return false; }
        updated.keepalive_interval = parse_int_or_default(form, "keepalive_interval", updated.keepalive_interval, 1, 600, error);
        if (!error.empty()) { message = error; return false; }

        updated.web_ui.enabled = form_has_checkbox(form, "web_ui_enabled");
        updated.web_ui.host = form_value_or_default(form, "web_ui_host", updated.web_ui.host);
        updated.web_ui.port = static_cast<uint16_t>(parse_int_or_default(form, "web_ui_port", updated.web_ui.port, 1, 65535, error));
        if (!error.empty()) { message = error; return false; }
        updated.web_ui.auto_start_tunnel = form_has_checkbox(form, "web_ui_auto_start_tunnel");

        updated.obfuscate_chain.clear();
        for (const char* slot : {"obfuscate_slot1", "obfuscate_slot2", "obfuscate_slot3"}) {
            const auto mode = parse_obfuscation_name(form_value_or_default(form, slot, "none"));
            if (mode != ObfuscateMode::NONE) {
                updated.obfuscate_chain.push_back(mode);
            }
        }

        Logger::set_level(updated.log_level);
        set_config(updated);
        message = "表单配置已写入内存";
        return true;
    }

    bool start(std::string& message) {
        if (runtime_thread_.joinable() && !running_.load()) {
            runtime_thread_.join();
            std::lock_guard<std::mutex> lock(mutex_);
            runtime_.reset();
        }

        std::lock_guard<std::mutex> lock(mutex_);
        if (running_.load()) {
            message = "隧道已在运行";
            return true;
        }

        try {
            Logger::set_level(cfg_.log_level);
            runtime_ = std::make_unique<ManagedRuntime>(cfg_);
        } catch (const std::exception& e) {
            message = std::string("启动失败: ") + e.what();
            return false;
        }

        stop_requested_ = false;
        running_ = true;
        last_message_ = "隧道运行中";

        runtime_thread_ = std::thread([this]() {
            std::string final_message = "隧道已停止";
            try {
                runtime_->run();
                final_message = stop_requested_ ? "隧道已停止" : "隧道已退出";
            } catch (const std::exception& e) {
                final_message = std::string("运行失败: ") + e.what();
            } catch (...) {
                final_message = "运行失败: 未知异常";
            }

            std::lock_guard<std::mutex> inner_lock(mutex_);
            running_ = false;
            last_message_ = final_message;
        });

        message = "隧道已启动";
        return true;
    }

    bool stop(std::string& message) {
        ManagedRuntime* runtime_ptr = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stop_requested_ = true;
            runtime_ptr = runtime_.get();
        }

        if (runtime_ptr) {
            runtime_ptr->stop();
        }

        if (runtime_thread_.joinable()) {
            runtime_thread_.join();
        }

        std::lock_guard<std::mutex> lock(mutex_);
        running_ = false;
        runtime_.reset();
        last_message_ = runtime_ptr ? "隧道已停止" : "隧道未运行";
        message = last_message_;
        return true;
    }


    bool restart(std::string& message) {
        std::string stop_message;
        stop(stop_message);
        return start(message);
    }

    RuntimeStatus status() const {
        std::lock_guard<std::mutex> lock(mutex_);
        RuntimeStatus status;
        status.running = running_.load();
        status.session_count = runtime_ ? runtime_->session_count() : 0;
        status.message = last_message_;
        status.config_path = config_path_;
        return status;
    }

private:
    static Config default_config() {
#ifdef VPN_SERVER_BUILD
        return Config::load_server_defaults();
#else
        return Config::load_client_defaults();
#endif
    }

    std::string config_path_;
    mutable std::mutex mutex_;
    Config cfg_;
    std::unique_ptr<ManagedRuntime> runtime_;
    std::thread runtime_thread_;
    std::atomic<bool> running_{false};
    bool stop_requested_ = false;
    std::string last_message_ = "未启动";
};

struct HttpRequest {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
};

struct HttpResponse {
    int status = 200;
    std::string content_type = "text/html; charset=utf-8";
    std::string body;
};

class WebUiServer {
public:
    WebUiServer(RuntimeController& controller, std::string host, uint16_t port)
        : controller_(controller), host_(std::move(host)), port_(port) {}

    void run() {
        asio::ip::address bind_address = asio::ip::make_address(host_);
        tcp::endpoint endpoint(bind_address, port_);

        acceptor_ = std::make_unique<tcp::acceptor>(io_);
        acceptor_->open(endpoint.protocol());
        acceptor_->set_option(tcp::acceptor::reuse_address(true));
        acceptor_->bind(endpoint);
        acceptor_->listen(asio::socket_base::max_listen_connections);

        running_ = true;
        VPN_INFO("Web UI listening on http://{}:{}", host_, port_);

        while (running_) {
            asio::error_code ec;
            tcp::socket socket(io_);
            acceptor_->accept(socket, ec);
            if (ec) {
                if (running_) {
                    VPN_WARN("Web UI accept failed: {}", ec.message());
                }
                continue;
            }
            std::thread([this, sock = std::move(socket)]() mutable {
                handle_connection(std::move(sock));
            }).detach();
        }
    }

    void stop() {
        running_ = false;
        asio::error_code ec;
        if (acceptor_) {
            acceptor_->close(ec);
        }
        io_.stop();
    }

private:
    std::optional<HttpRequest> read_request(tcp::socket& socket) {
        asio::streambuf buffer;
        asio::error_code ec;
        asio::read_until(socket, buffer, "\r\n\r\n", ec);
        if (ec) {
            return std::nullopt;
        }

        HttpRequest request;
        std::istream stream(&buffer);
        std::string request_line;
        std::getline(stream, request_line);
        request_line = trim_copy(request_line);

        std::istringstream request_line_stream(request_line);
        std::string http_version;
        request_line_stream >> request.method >> request.path >> http_version;
        if (request.method.empty() || request.path.empty()) {
            return std::nullopt;
        }

        std::string header_line;
        size_t content_length = 0;
        while (std::getline(stream, header_line)) {
            header_line = trim_copy(header_line);
            if (header_line.empty()) {
                break;
            }
            const auto colon = header_line.find(':');
            if (colon == std::string::npos) {
                continue;
            }
            const auto key = lower_copy(trim_copy(header_line.substr(0, colon)));
            const auto value = trim_copy(header_line.substr(colon + 1));
            request.headers[key] = value;
            if (key == "content-length") {
                content_length = static_cast<size_t>(std::stoul(value));
            }
        }

        request.body.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
        if (request.body.size() < content_length) {
            const size_t missing = content_length - request.body.size();
            std::string remainder(missing, '\0');
            asio::read(socket, asio::buffer(remainder.data(), remainder.size()), ec);
            if (ec) {
                return std::nullopt;
            }
            request.body += remainder;
        }

        const auto query_pos = request.path.find('?');
        if (query_pos != std::string::npos) {
            request.path = request.path.substr(0, query_pos);
        }
        return request;
    }

    void write_response(tcp::socket& socket, const HttpResponse& response) {
        std::ostringstream out;
        const char* status_text = response.status == 200 ? "OK"
                                : response.status == 404 ? "Not Found"
                                : response.status == 405 ? "Method Not Allowed"
                                : "Bad Request";

        out << "HTTP/1.1 " << response.status << ' ' << status_text << "\r\n";
        out << "Content-Type: " << response.content_type << "\r\n";
        out << "Cache-Control: no-store\r\n";
        out << "Content-Length: " << response.body.size() << "\r\n";
        out << "Connection: close\r\n\r\n";
        out << response.body;

        asio::error_code ec;
        const auto payload = out.str();
        asio::write(socket, asio::buffer(payload), ec);
        socket.shutdown(tcp::socket::shutdown_both, ec);
        socket.close(ec);
    }

    std::string render_text_input(const std::string& label,
                                  const std::string& name,
                                  const std::string& value,
                                  const std::string& placeholder = std::string()) const {
        std::ostringstream out;
        out << "<label><span>" << html_escape(label) << "</span>"
            << "<input type='text' name='" << html_escape(name) << "' value='" << html_escape(value) << "'";
        if (!placeholder.empty()) {
            out << " placeholder='" << html_escape(placeholder) << "'";
        }
        out << "></label>";
        return out.str();
    }

    std::string render_number_input(const std::string& label,
                                    const std::string& name,
                                    int value,
                                    int min_value,
                                    int max_value) const {
        std::ostringstream out;
        out << "<label><span>" << html_escape(label) << "</span>"
            << "<input type='number' name='" << html_escape(name) << "' value='" << value
            << "' min='" << min_value << "' max='" << max_value << "'></label>";
        return out.str();
    }

    std::string render_checkbox(const std::string& label,
                                const std::string& name,
                                bool checked) const {
        std::ostringstream out;
        out << "<label class='checkbox'>"
            << "<input type='checkbox' name='" << html_escape(name) << "'" << checked_attr(checked) << ">"
            << "<span>" << html_escape(label) << "</span></label>";
        return out.str();
    }

    std::string render_select(const std::string& label,
                              const std::string& name,
                              const std::vector<std::pair<std::string, std::string>>& options,
                              const std::string& current) const {
        std::ostringstream out;
        out << "<label><span>" << html_escape(label) << "</span><select name='" << html_escape(name) << "'>";
        for (const auto& option : options) {
            out << "<option value='" << html_escape(option.first) << "'" << selected_attr(current, option.first) << ">"
                << html_escape(option.second) << "</option>";
        }
        out << "</select></label>";
        return out.str();
    }

    std::string render_dashboard(const std::optional<Notice>& notice) const {
        const auto cfg = controller_.current_config();
        const auto status = controller_.status();

        const std::string status_class = status.running ? "running" : "stopped";
        const std::string status_text = status.running ? "运行中" : "已停止";

        std::ostringstream html;
        html << "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>"
             << "<meta name='viewport' content='width=device-width,initial-scale=1'>"
             << "<title>" << kRoleTitle << " Web UI</title>"
             << "<style>"
             << "body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#0f172a;color:#e2e8f0;}"
             << ".wrap{max-width:1180px;margin:0 auto;padding:28px 20px 40px;}"
             << ".hero,.panel{background:#111827;border:1px solid #1f2937;border-radius:18px;box-shadow:0 10px 30px rgba(0,0,0,.25);}"
             << ".hero{padding:24px;margin-bottom:20px;}"
             << ".panel{padding:20px;margin-bottom:18px;}"
             << "h1,h2{margin:0 0 14px;}"
             << ".subtitle{color:#94a3b8;line-height:1.6;}"
             << ".status-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-top:18px;}"
             << ".stat{padding:14px 16px;border-radius:14px;background:#0b1220;border:1px solid #1e293b;}"
             << ".stat .k{display:block;font-size:12px;color:#94a3b8;margin-bottom:6px;text-transform:uppercase;letter-spacing:.08em;}"
             << ".stat .v{font-size:18px;font-weight:700;word-break:break-word;}"
             << ".badge{display:inline-flex;align-items:center;padding:6px 12px;border-radius:999px;font-size:13px;font-weight:700;}"
             << ".badge.running{background:rgba(34,197,94,.15);color:#4ade80;}"
             << ".badge.stopped{background:rgba(248,113,113,.15);color:#f87171;}"
             << ".notice{padding:14px 16px;border-radius:14px;margin-bottom:18px;font-weight:600;}"
             << ".notice.ok{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.35);color:#86efac;}"
             << ".notice.err{background:rgba(248,113,113,.12);border:1px solid rgba(248,113,113,.35);color:#fca5a5;}"
             << ".actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:12px;}"
             << ".actions form,.inline{margin:0;}"
             << "button{border:none;border-radius:12px;padding:12px 16px;font-size:14px;font-weight:700;cursor:pointer;background:#2563eb;color:#fff;}"
             << "button.secondary{background:#334155;}button.warn{background:#ea580c;}button.good{background:#16a34a;}"
             << "form.config{display:grid;gap:18px;}"
             << ".section-title{font-size:15px;font-weight:700;color:#cbd5e1;margin-bottom:8px;}"
             << ".field-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;}"
             << "label{display:flex;flex-direction:column;gap:8px;font-size:14px;color:#cbd5e1;}"
             << "label span{font-weight:600;}"
             << "input,select,textarea{width:100%;box-sizing:border-box;border-radius:12px;border:1px solid #334155;background:#020617;color:#e2e8f0;padding:12px 14px;font-size:14px;}"
             << "textarea{min-height:220px;resize:vertical;font-family:Consolas,monospace;}"
             << ".checkbox{flex-direction:row;align-items:center;gap:10px;padding-top:28px;}"
             << ".checkbox input{width:auto;}"
             << ".helper{color:#94a3b8;font-size:13px;line-height:1.6;margin-top:8px;}"

             << "@media (max-width:720px){.wrap{padding:16px 12px 24px;}}"
             << "</style></head><body><div class='wrap'>";

        if (notice && !notice->text.empty()) {
            html << "<div class='notice " << (notice->ok ? "ok" : "err") << "'>" << html_escape(notice->text) << "</div>";
        }

        html << "<section class='hero'>"
             << "<h1>" << kRoleTitle << " Web UI</h1>"
             << "<div class='subtitle'>在浏览器中完成隧道启动/停止、配置编辑、混淆链顺序调整、TUN 参数修改与 Web UI 管理。"
             << "</div><div class='status-grid'>"
             << "<div class='stat'><span class='k'>角色</span><span class='v'>" << html_escape(controller_.role_name()) << "</span></div>"
             << "<div class='stat'><span class='k'>当前状态</span><span class='v'><span id='runtimeBadge' class='badge " << status_class << "'>" << status_text << "</span></span></div>"
             << "<div class='stat'><span class='k'>活动会话</span><span id='sessionCount' class='v'>" << status.session_count << "</span></div>"
             << "<div class='stat'><span class='k'>配置文件</span><span class='v'>" << html_escape(status.config_path) << "</span></div>"
             << "<div class='stat'><span class='k'>Web UI 监听</span><span class='v'>http://" << html_escape(host_) << ':' << port_ << "</span></div>"
             << "<div class='stat'><span class='k'>运行消息</span><span id='runtimeMessage' class='v'>" << html_escape(status.message) << "</span></div>"
             << "</div></section>";

        html << "<section class='panel'><h2>运行控制</h2>"
             << "<div class='subtitle'>保存配置后，如已改动监听地址、加密方式、混淆链、TUN 参数或 Web UI 绑定，请点击“重启隧道”以应用运行时变更。Web UI 的 host/port 变更需重启整个进程后生效。</div>"
             << "<div class='actions'>"
             << "<form method='post' action='/api/start'><button class='good' type='submit'>启动隧道</button></form>"
             << "<form method='post' action='/api/stop'><button class='warn' type='submit'>停止隧道</button></form>"
             << "<form method='post' action='/api/restart'><button type='submit'>重启隧道</button></form>"
             << "<form method='post' action='/api/reload'><button class='secondary' type='submit'>从磁盘重新加载</button></form>"
             << "</div></section>";

        html << "<section class='panel'><h2>全部控制项</h2><form class='config' method='post' action='/api/config/save'>";

#ifdef VPN_SERVER_BUILD
        html << "<div><div class='section-title'>网络监听</div><div class='field-grid'>"
             << render_text_input("监听地址", "listen_host", cfg.listen_host, "0.0.0.0")
             << render_number_input("监听端口", "listen_port", cfg.listen_port, 1, 65535)
             << "</div></div>";
#endif
#ifdef VPN_CLIENT_BUILD
        html << "<div><div class='section-title'>远端服务端</div><div class='field-grid'>"
             << render_text_input("服务端地址", "peer_host", cfg.peer_host, "YOUR_SERVER_IP")
             << render_number_input("服务端端口", "peer_port", cfg.peer_port, 1, 65535)
             << "</div></div>";
#endif

        html << "<div><div class='section-title'>加密与混淆</div><div class='field-grid'>"
             << render_select("加密算法", "cipher", {{"chacha20-poly1305", "ChaCha20-Poly1305"}, {"aes-256-gcm", "AES-256-GCM"}}, to_string(cfg.cipher))
             << render_text_input("预共享密钥（PSK）", "psk", cfg.psk, "建议填写高强度随机字符串")
             << render_select("混淆链槽位 1", "obfuscate_slot1", {{"none", "禁用"}, {"padding", "Padding / 流量整形"}, {"websocket", "WebSocket 帧"}, {"http", "HTTP POST 伪装"}}, obfuscation_slot_value(cfg.obfuscate_chain, 0))
             << render_select("混淆链槽位 2", "obfuscate_slot2", {{"none", "禁用"}, {"padding", "Padding / 流量整形"}, {"websocket", "WebSocket 帧"}, {"http", "HTTP POST 伪装"}}, obfuscation_slot_value(cfg.obfuscate_chain, 1))
             << render_select("混淆链槽位 3", "obfuscate_slot3", {{"none", "禁用"}, {"padding", "Padding / 流量整形"}, {"websocket", "WebSocket 帧"}, {"http", "HTTP POST 伪装"}}, obfuscation_slot_value(cfg.obfuscate_chain, 2))
             << "</div><div class='helper'>槽位顺序即发送时的封装顺序，例如：padding → websocket → http。</div>"
             << "<div class='actions inline'><button type='button' onclick='generatePsk()'>生成随机 PSK</button></div></div>";

        html << "<div><div class='section-title'>TUN 配置</div><div class='field-grid'>"
             << render_text_input("网卡名称", "tun_name", cfg.tun.name)
             << render_text_input("隧道地址", "tun_address", cfg.tun.address)
             << render_text_input("子网掩码", "tun_netmask", cfg.tun.netmask)
             << render_number_input("MTU", "tun_mtu", cfg.tun.mtu, 576, 9000)
             << "</div></div>";

        html << "<div><div class='section-title'>高级参数</div><div class='field-grid'>"
             << render_select("日志级别", "log_level", {{"0", "Trace"}, {"1", "Info"}, {"2", "Warn"}, {"3", "Error"}}, std::to_string(cfg.log_level))
             << render_number_input("握手超时（秒）", "handshake_timeout", cfg.handshake_timeout, 1, 120)
             << render_number_input("Keepalive（秒）", "keepalive_interval", cfg.keepalive_interval, 1, 600)
             << "</div></div>";

        html << "<div><div class='section-title'>Web UI</div><div class='field-grid'>"
             << render_checkbox("启用 Web UI", "web_ui_enabled", cfg.web_ui.enabled)
             << render_text_input("Web UI Host", "web_ui_host", cfg.web_ui.host, "127.0.0.1")
             << render_number_input("Web UI Port", "web_ui_port", cfg.web_ui.port, 1, 65535)
             << render_checkbox("进程启动时自动启动隧道", "web_ui_auto_start_tunnel", cfg.web_ui.auto_start_tunnel)
             << "</div><div class='helper'>建议默认绑定到 127.0.0.1；若改为 0.0.0.0，请自行通过反向代理、防火墙或内网访问控制进行保护。</div></div>";

        html << "<div class='actions'><button type='submit'>保存全部配置</button></div></form></section>";

        html << "<section class='panel'><h2>当前 YAML 预览</h2>"
             << "<textarea readonly>" << html_escape(cfg.to_yaml_string()) << "</textarea>"
             << "</section>";

        html << "</div><script>"
             << "async function refreshStatus(){try{const r=await fetch('/api/status',{cache:'no-store'});if(!r.ok)return;const s=await r.json();"
             << "const badge=document.getElementById('runtimeBadge');const msg=document.getElementById('runtimeMessage');const count=document.getElementById('sessionCount');"
             << "badge.textContent=s.running?'运行中':'已停止';badge.className='badge '+(s.running?'running':'stopped');msg.textContent=s.message;count.textContent=s.session_count;}catch(e){}}"
             << "function generatePsk(){const out=[];const bytes=new Uint8Array(32);window.crypto.getRandomValues(bytes);for(const b of bytes){out.push(b.toString(16).padStart(2,'0'));}document.querySelector('input[name=psk]').value=out.join('');}"
             << "setInterval(refreshStatus,2000);window.addEventListener('load',refreshStatus);"
             << "</script></body></html>";

        return html.str();
    }

    std::string render_status_json() const {
        const auto status = controller_.status();
        std::ostringstream json;
        json << "{";
        json << "\"running\":" << (status.running ? "true" : "false") << ',';
        json << "\"session_count\":" << status.session_count << ',';
        json << "\"message\":\"" << json_escape(status.message) << "\"";
        json << "}";
        return json.str();
    }

    HttpResponse handle_request(const HttpRequest& request) {
        if (request.method == "GET" && request.path == "/") {
            return HttpResponse{200, "text/html; charset=utf-8", render_dashboard(std::nullopt)};
        }
        if (request.method == "GET" && request.path == "/api/status") {
            return HttpResponse{200, "application/json; charset=utf-8", render_status_json()};
        }
        if (request.method != "POST") {
            return HttpResponse{405, "text/plain; charset=utf-8", "Method Not Allowed"};
        }

        Notice notice;
        std::string message;
        bool ok = true;

        if (request.path == "/api/start") {
            ok = controller_.start(message);
        } else if (request.path == "/api/stop") {
            ok = controller_.stop(message);
        } else if (request.path == "/api/restart") {
            ok = controller_.restart(message);
        } else if (request.path == "/api/reload") {
            ok = controller_.reload_from_disk(message);
        } else if (request.path == "/api/config/save") {
            ok = controller_.apply_form(parse_form_urlencoded(request.body), message);
            if (ok) {
                ok = controller_.save_to_disk(message);
            }
        } else {
            return HttpResponse{404, "text/plain; charset=utf-8", "Not Found"};
        }

        notice.ok = ok;
        notice.text = message;
        return HttpResponse{200, "text/html; charset=utf-8", render_dashboard(notice)};
    }

    void handle_connection(tcp::socket socket) {
        try {
            const auto request = read_request(socket);
            if (!request) {
                write_response(socket, HttpResponse{400, "text/plain; charset=utf-8", "Bad Request"});
                return;
            }
            write_response(socket, handle_request(*request));
        } catch (const std::exception& e) {
            VPN_WARN("Web UI request error: {}", e.what());
        }
    }

    RuntimeController& controller_;
    std::string host_;
    uint16_t port_ = 0;
    std::atomic<bool> running_{false};
    asio::io_context io_;
    std::unique_ptr<tcp::acceptor> acceptor_;
};

} // namespace

class WebUiApp::Impl {
public:
    explicit Impl(WebUiOptions options)
        : options_(std::move(options)), controller_(options_.config_path) {}

    void run() {
        Config cfg = controller_.current_config();
        if (!options_.host_override.empty()) {
            cfg.web_ui.host = options_.host_override;
        }
        if (options_.port_override != 0) {
            cfg.web_ui.port = options_.port_override;
        }
        if (options_.has_auto_start_override) {
            cfg.web_ui.auto_start_tunnel = options_.auto_start_override;
        }
        cfg.web_ui.enabled = true;
        controller_.set_config(cfg);
        Logger::set_level(cfg.log_level);

        web_server_ = std::make_unique<WebUiServer>(controller_, cfg.web_ui.host, cfg.web_ui.port);

        if (cfg.web_ui.auto_start_tunnel) {
            std::string message;
            controller_.start(message);
            VPN_INFO("Web UI auto-start: {}", message);
        }

        web_server_->run();
    }

    void stop() {
        if (web_server_) {
            web_server_->stop();
        }
        std::string ignored;
        controller_.stop(ignored);
    }

private:
    WebUiOptions options_;
    RuntimeController controller_;
    std::unique_ptr<WebUiServer> web_server_;
};

WebUiApp::WebUiApp(WebUiOptions options)
    : impl_(std::make_unique<Impl>(std::move(options))) {}

WebUiApp::~WebUiApp() = default;

void WebUiApp::run() {
    impl_->run();
}

void WebUiApp::stop() {
    impl_->stop();
}

} // namespace vpn
