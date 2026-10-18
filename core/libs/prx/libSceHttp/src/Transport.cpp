#include "Transport.hpp"
#include "HttpErrors.hpp"
#include "prx/libc/include/General.hpp"
#include "prx/libSceSsl/SslTypes.hpp"
#include <curl/curl.h>
#include <mbedtls/ssl.h>
#include <mbedtls/pem.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform_util.h>
#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstring>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

extern "C" int APS5_VABI sceNetCtlGetInfo(int code, NetCtlInfo* info);
extern "C" int __real_mbedtls_ssl_set_hostname(mbedtls_ssl_context* context, const char* hostname);

namespace {

enum class Kind { Context, Template, Connection, Request };

struct Settings {
    std::string agent;
    long version = CURL_HTTP_VERSION_1_1;
    std::uint32_t connectTimeout = 30000000;
    std::uint32_t receiveTimeout = 30000000;
    std::uint32_t resolveTimeout = 30000000;
    std::uint32_t sendTimeout = 30000000;
    int resolveRetry = 0;
    std::size_t headerLimit = 16384;
    std::size_t readBlock = INT_MAX;
    bool keepAlive = false;
    bool redirect = true;
    bool cookies = false;
    bool inflate = true;
    bool chunked = false;
    bool nonblock = false;
    bool autoProxy = false;
    HttpsCallback sslCallback = nullptr;
    void* sslArgument = nullptr;
    std::shared_ptr<HttpEventSink> epoll;
    HttpEpollHandle epollHandle = nullptr;
    void* epollArgument = nullptr;
    std::uint32_t verify = 0xfd;
    std::uint32_t tlsVersion = 0;
    std::uint32_t minimumTlsVersion = 0;
    std::string authorities;
    std::vector<unsigned char> certificate;
    std::vector<unsigned char> key;
    std::vector<std::pair<std::string, std::string>> headers;

    ~Settings() { if (!key.empty()) mbedtls_platform_zeroize(key.data(), key.size()); }
};

struct Transfer {
    CURL* easy = curl_easy_init();
    CURLM* multi = curl_multi_init();
    curl_slist* outgoing = nullptr;
    bool attached = false;
    bool ready = false;
    bool done = false;
    bool redirect = false;
    bool location = false;
    bool discard = false;
    bool paused = false;
    bool tunnel = false;
    bool resolving = false;
    bool sending = false;
    bool sent = false;
    bool retrying = false;
    int resolveRetries = 0;
    curl_off_t lookupBaseline = 0;
    curl_off_t sendBaseline = 0;
    std::chrono::steady_clock::time_point resolveStarted;
    std::chrono::steady_clock::time_point sendStarted;
    int status = 0;
    int error = 0;
    int nativeError = 0;
    std::uint32_t verifyError = 0;
    std::exception_ptr callbackError;
    std::string peerHostname;
    std::size_t headerLimit = 0;
    std::string headers;
    std::vector<char> body;
    std::size_t consumed = 0;

    ~Transfer() {
        if (attached) curl_multi_remove_handle(multi, easy);
        if (easy) curl_easy_cleanup(easy);
        if (multi) curl_multi_cleanup(multi);
        curl_slist_free_all(outgoing);
    }
};

struct CookieStore {
    CURLSH* share = curl_share_init();
    std::mutex mutex;

    static void Lock(CURL*, curl_lock_data, curl_lock_access, void* value) {
        static_cast<CookieStore*>(value)->mutex.lock();
    }
    static void Unlock(CURL*, curl_lock_data, void* value) {
        static_cast<CookieStore*>(value)->mutex.unlock();
    }
    CookieStore() {
        if (!share || curl_share_setopt(share, CURLSHOPT_LOCKFUNC, Lock) != CURLSHE_OK ||
            curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, Unlock) != CURLSHE_OK ||
            curl_share_setopt(share, CURLSHOPT_USERDATA, this) != CURLSHE_OK ||
            curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE) != CURLSHE_OK) {
            if (share) curl_share_cleanup(share);
            throw std::bad_alloc();
        }
    }
    ~CookieStore() { curl_share_cleanup(share); }
};

struct Object {
    Kind kind;
    int id = 0;
    int parent = 0;
    int context = 0;
    int sslContext = 0;
    std::map<void*, SceSsl::CaList> caLists;
    Settings settings;
    std::string url;
    std::string method;
    std::string proxy;
    std::uint64_t contentLength = 0;
    std::recursive_mutex mutex;
    std::atomic<unsigned> callbacks{0};
    std::atomic<bool> aborted{false};
    std::shared_ptr<CookieStore> cookieStore;
    std::shared_ptr<Object> root;
    std::unique_ptr<Transfer> transfer;
    std::shared_ptr<std::atomic<bool>> eventAlive = std::make_shared<std::atomic<bool>>(true);
    std::jthread worker;

    explicit Object(Kind value) : kind(value) {}
    ~Object() {
        aborted = true;
        *eventAlive = false;
        for (const auto& [pointer, list] : caLists) SslReleaseCaList_nid_no_patch(sslContext, list);
    }
};

struct ParsedCertificate {
    mbedtls_x509_crt value{};
    ~ParsedCertificate() { mbedtls_x509_crt_free(&value); }
};

struct CallbackScope;
thread_local CallbackScope* activeCallback = nullptr;
thread_local Object* activeRequest = nullptr;

struct TransferScope {
    Object* previous = activeRequest;
    explicit TransferScope(Object& request) { activeRequest = &request; }
    ~TransferScope() { activeRequest = previous; }
};

struct CallbackScope {
    CallbackScope* previous = activeCallback;
    Object& object;
    explicit CallbackScope(Object& value) : object(value) {
        ++object.callbacks;
        ++object.root->callbacks;
        activeCallback = this;
    }
    ~CallbackScope() {
        activeCallback = previous;
        --object.root->callbacks;
        --object.callbacks;
    }
};

bool InCallback(int id) {
    for (auto* scope = activeCallback; scope; scope = scope->previous)
        if (scope->object.id == id) return true;
    return false;
}

std::uint32_t VerificationBits(std::uint32_t flags) {
    std::uint32_t result = 0;
    if (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) result |= 4;
    if (flags & MBEDTLS_X509_BADCERT_EXPIRED) result |= 8;
    if (flags & MBEDTLS_X509_BADCERT_FUTURE) result |= 16;
    if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) result |= 32;
    if (flags & ~(MBEDTLS_X509_BADCERT_CN_MISMATCH | MBEDTLS_X509_BADCERT_EXPIRED |
                  MBEDTLS_X509_BADCERT_FUTURE | MBEDTLS_X509_BADCERT_NOT_TRUSTED)) result |= 2;
    return result;
}

int VerifyCertificate(void* argument, mbedtls_x509_crt* certificate, int depth, std::uint32_t* flags) noexcept {
    auto& request = *static_cast<Object*>(argument);
    const auto options = request.settings.verify;
    if (!depth && !(options & 0x80) && (options & 4)) {
        std::uint32_t nameFlags = 0;
        const int result = mbedtls_x509_crt_verify(certificate, nullptr, nullptr,
            request.transfer->peerHostname.c_str(), &nameFlags, nullptr, nullptr);
        if (result != 0 && result != MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
            request.transfer->verifyError |= MBEDTLS_X509_BADCERT_OTHER;
            return MBEDTLS_ERR_X509_FATAL_ERROR;
        }
        *flags |= nameFlags & MBEDTLS_X509_BADCERT_CN_MISMATCH;
    }
    if (!(options & 0x01)) *flags = 0;
    if (!(options & 0x04)) *flags &= ~MBEDTLS_X509_BADCERT_CN_MISMATCH;
    if (!(options & 0x08)) *flags &= ~MBEDTLS_X509_BADCERT_EXPIRED;
    if (!(options & 0x10)) *flags &= ~MBEDTLS_X509_BADCERT_FUTURE;
    if (!(options & 0x20)) *flags &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    request.transfer->verifyError |= *flags;
    if (request.settings.sslCallback) {
        *flags = 0;
        if (depth) return 0;
        SceSsl::CaList chain{};
        try {
            std::string pem;
            for (const auto* entry = certificate; entry && entry->raw.p; entry = entry->next) {
                std::size_t length = 0;
                mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n",
                    entry->raw.p, entry->raw.len, nullptr, 0, &length);
                std::vector<unsigned char> encoded(length);
                if (mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n",
                    entry->raw.p, entry->raw.len, encoded.data(), encoded.size(), &length) != 0)
                    return MBEDTLS_ERR_X509_FATAL_ERROR;
                pem.append(reinterpret_cast<char*>(encoded.data()), length - 1);
            }
            SceSsl::Data input{reinterpret_cast<std::uint8_t*>(pem.data()), pem.size() + 1};
            if (SslImportCaList_nid_no_patch(request.root->sslContext, &input, &chain) != 0)
                return MBEDTLS_ERR_X509_FATAL_ERROR;
            CallbackScope scope(request);
            const int result = request.settings.sslCallback(request.root->sslContext, VerificationBits(request.transfer->verifyError),
                chain.certs, chain.num, request.settings.sslArgument);
            SslReleaseCaList_nid_no_patch(request.root->sslContext, chain);
            if (result || request.aborted) {
                if (!request.transfer->verifyError) request.transfer->verifyError = MBEDTLS_X509_BADCERT_OTHER;
                return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            }
            request.transfer->verifyError = 0;
        } catch (...) {
            if (chain.certs) SslReleaseCaList_nid_no_patch(request.root->sslContext, chain);
            request.transfer->callbackError = std::current_exception();
            return MBEDTLS_ERR_X509_FATAL_ERROR;
        }
    }
    return 0;
}

CURLcode ConfigureTls(CURL*, void* context, void* argument) {
    mbedtls_ssl_conf_verify(static_cast<mbedtls_ssl_config*>(context), VerifyCertificate, argument);
    return CURLE_OK;
}

std::mutex registryMutex;
std::map<int, std::shared_ptr<Object>> registry;

bool InitializeCurl() {
    static const bool ready = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
    return ready;
}

std::shared_ptr<Object> Find(int id, Kind kind) {
    std::lock_guard lock(registryMutex);
    const auto found = registry.find(id);
    return found != registry.end() && found->second->kind == kind ? found->second : nullptr;
}

std::shared_ptr<Object> FindAny(int id) {
    std::lock_guard lock(registryMutex);
    const auto found = registry.find(id);
    return found == registry.end() ? nullptr : found->second;
}

int Insert(std::shared_ptr<Object> object) {
    std::lock_guard lock(registryMutex);
    if (!registry.contains(object->parent)) return ERROR_INVALID_ID;
    object->cookieStore = registry.at(object->parent)->cookieStore;
    const auto& parent = registry.at(object->parent);
    object->root = parent->kind == Kind::Context ? parent : parent->root;
    const int id = HttpNextHandle_nid_no_patch();
    object->id = id;
    registry.emplace(id, std::move(object));
    return id;
}

bool HasCallbacks(int id) {
    std::lock_guard lock(registryMutex);
    while (id) {
        if (HttpHasCallback_nid_no_patch(id)) return true;
        const auto found = registry.find(id);
        if (found == registry.end()) break;
        id = found->second->parent;
    }
    return false;
}

bool EqualName(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        const auto lower = [](char c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; };
        if (lower(a[i]) != lower(b[i])) return false;
    }
    return true;
}

bool Token(std::string_view text) {
    if (text.empty()) return false;
    for (unsigned char c : text)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            std::strchr("!#$%&'*+-.^_`|~", c))) return false;
    return true;
}

bool Field(std::string_view text) {
    return std::none_of(text.begin(), text.end(), [](unsigned char c) { return (c < 32 && c != '\t') || c == 127; });
}

std::string_view Trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
    return value;
}

int Framing(const Object& request, std::size_t size, bool& chunked, bool& length, std::string& encoding) {
    for (const auto& [name, value] : request.settings.headers) {
        if (EqualName(name, "Content-Length")) {
            auto values = std::string_view(value);
            for (;;) {
                const auto comma = values.find(',');
                const auto item = Trim(values.substr(0, comma));
                std::uint64_t declared = 0;
                const auto parsed = std::from_chars(item.data(), item.data() + item.size(), declared);
                if (item.empty() || parsed.ec != std::errc{} || parsed.ptr != item.data() + item.size() || declared != size)
                    return ERROR_INVALID_VALUE;
                length = true;
                if (comma == std::string_view::npos) break;
                values.remove_prefix(comma + 1);
            }
        }
        if (EqualName(name, "Transfer-Encoding")) {
            if (!encoding.empty()) encoding += ',';
            if (Trim(value).empty()) return ERROR_INVALID_VALUE;
            encoding += value;
        }
    }
    if (!encoding.empty()) {
        auto values = std::string_view(encoding);
        bool found = false;
        for (;;) {
            const auto comma = values.find(',');
            const auto item = Trim(values.substr(0, comma));
            if (item.empty() || found) return ERROR_INVALID_VALUE;
            found = EqualName(item, "chunked");
            if (comma == std::string_view::npos) break;
            values.remove_prefix(comma + 1);
        }
        if (!found) return ERROR_INVALID_VALUE;
        chunked = true;
    }
    if ((length && chunked) || (chunked && request.settings.version == CURL_HTTP_VERSION_1_0)) return ERROR_INVALID_VALUE;
    if (!chunked && !length && size != request.contentLength) return ERROR_INVALID_VALUE;
    return 0;
}

std::string NormalizeUrl(const char* text, bool originOnly) {
    if (!text || !InitializeCurl()) return {};
    std::unique_ptr<CURLU, decltype(&curl_url_cleanup)> url(curl_url(), curl_url_cleanup);
    if (!url || curl_url_set(url.get(), CURLUPART_URL, text, CURLU_DISALLOW_USER | CURLU_NON_SUPPORT_SCHEME) != CURLUE_OK) return {};
    char* value = nullptr;
    if (curl_url_get(url.get(), CURLUPART_SCHEME, &value, 0) != CURLUE_OK) return {};
    const std::string scheme(value);
    curl_free(value);
    if (scheme != "http" && scheme != "https") return {};
    curl_url_set(url.get(), CURLUPART_FRAGMENT, nullptr, 0);
    if (originOnly) {
        curl_url_set(url.get(), CURLUPART_PATH, "/", 0);
        curl_url_set(url.get(), CURLUPART_QUERY, nullptr, 0);
    }
    if (curl_url_get(url.get(), CURLUPART_URL, &value, 0) != CURLUE_OK) return {};
    std::string result(value);
    curl_free(value);
    return result;
}

const char* Method(int method) {
    constexpr const char* methods[] = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE", "CONNECT"};
    return method >= 0 && method < 8 ? methods[method] : nullptr;
}

int ProxyConfiguration(std::string& proxy) {
    NetCtlInfo info{};
    if (sceNetCtlGetInfo(19, &info) != 0) return ERROR_NETWORK;
    std::uint32_t mode = 0;
    std::memcpy(&mode, info.opaque, sizeof(mode));
    if (!mode) return 0;
    if (mode != 1) return ERROR_INVALID_VALUE;
    if (sceNetCtlGetInfo(20, &info) != 0) return ERROR_NETWORK;
    const auto* end = static_cast<const std::uint8_t*>(std::memchr(info.opaque, 0, sizeof(info.opaque)));
    if (!end || end == info.opaque) return ERROR_INVALID_VALUE;
    std::string host(reinterpret_cast<const char*>(info.opaque), static_cast<std::size_t>(end - info.opaque));
    if (host.find(':') != std::string::npos && !host.starts_with('[')) host = '[' + host + ']';
    if (sceNetCtlGetInfo(21, &info) != 0) return ERROR_NETWORK;
    std::uint16_t port = 0;
    std::memcpy(&port, info.opaque, sizeof(port));
    if (!port) return ERROR_INVALID_VALUE;
    proxy = NormalizeUrl(("http://" + host + ':' + std::to_string(port) + '/').c_str(), true);
    return proxy.empty() ? ERROR_INVALID_VALUE : 0;
}

std::string TunnelUrl(const char* text, bool absolute) {
    if (!absolute && (std::strpbrk(text, "/?#@\\") || !std::strchr(text, ':'))) return {};
    const auto input = absolute ? std::string(text) : "http://" + std::string(text) + '/';
    const auto normalized = NormalizeUrl(input.c_str(), true);
    if (normalized.empty()) return {};
    std::unique_ptr<CURLU, decltype(&curl_url_cleanup)> url(curl_url(), curl_url_cleanup);
    if (!url || curl_url_set(url.get(), CURLUPART_URL, normalized.c_str(), 0) != CURLUE_OK) return {};
    char* host = nullptr;
    char* port = nullptr;
    if (curl_url_get(url.get(), CURLUPART_HOST, &host, 0) != CURLUE_OK) return {};
    const auto result = curl_url_get(url.get(), CURLUPART_PORT, &port, absolute ? CURLU_DEFAULT_PORT : 0);
    std::string output;
    if (result == CURLUE_OK && std::strcmp(port, "0") != 0) output = "http://" + std::string(host) + ':' + port + '/';
    curl_free(host);
    curl_free(port);
    return output;
}

int NewRequest(int connection, const char* method, const char* location, std::uint64_t length, bool absolute) {
    auto parent = Find(connection, Kind::Connection);
    if (!parent) return ERROR_INVALID_ID;
    if (!method || !location || !Token(method)) return ERROR_INVALID_VALUE;
    auto request = std::make_shared<Object>(Kind::Request);
    {
        std::lock_guard lock(parent->mutex);
        request->settings = parent->settings;
        request->context = parent->context;
        if (EqualName(method, "CONNECT")) {
            if (length) return ERROR_INVALID_VALUE;
            request->url = TunnelUrl(location, absolute);
            request->proxy = parent->url;
        } else {
            if (!absolute && location[0] != '/') return ERROR_INVALID_URL;
            const auto url = absolute ? std::string(location) : parent->url.substr(0, parent->url.size() - 1) + location;
            request->url = NormalizeUrl(url.c_str(), false);
        }
    }
    if (request->url.empty()) return ERROR_INVALID_URL;
    request->parent = connection;
    request->method = method;
    request->contentLength = length;
    return Insert(std::move(request));
}

std::size_t Header(char* bytes, std::size_t size, std::size_t count, void* argument) noexcept {
    auto& transfer = *static_cast<Transfer*>(argument);
    const auto length = size * count;
    try {
        const std::string_view line(bytes, length);
        if (transfer.ready) return length;
        if (line.starts_with("HTTP/")) {
            transfer.headers.clear();
            transfer.location = false;
            transfer.discard = false;
            const auto space = line.find(' ');
            if (space == std::string_view::npos || line.size() - space < 4) return 0;
            const auto parsed = std::from_chars(line.data() + space + 1, line.data() + space + 4, transfer.status);
            if (parsed.ec != std::errc{}) return 0;
        }
        if (length > transfer.headerLimit - std::min(transfer.headers.size(), transfer.headerLimit)) {
            transfer.error = ERROR_OUT_OF_MEMORY;
            return 0;
        }
        transfer.headers.append(bytes, length);
        if (line.size() >= 9 && EqualName(line.substr(0, 9), "Location:")) transfer.location = true;
        if (line == "\r\n" && transfer.status >= 200) {
            transfer.discard = transfer.redirect && transfer.location &&
                (transfer.status == 301 || transfer.status == 302 || transfer.status == 303 || transfer.status == 307 || transfer.status == 308);
            transfer.ready = !transfer.discard;
        }
        return length;
    } catch (...) {
        transfer.error = ERROR_OUT_OF_MEMORY;
        return 0;
    }
}

std::size_t Body(char* bytes, std::size_t size, std::size_t count, void* argument) noexcept {
    auto& transfer = *static_cast<Transfer*>(argument);
    if (transfer.discard) return size * count;
    if (transfer.consumed != transfer.body.size()) {
        transfer.paused = true;
        return CURL_WRITEFUNC_PAUSE;
    }
    try {
        transfer.body.assign(bytes, bytes + size * count);
        transfer.consumed = 0;
        return size * count;
    } catch (...) {
        transfer.error = ERROR_OUT_OF_MEMORY;
        return 0;
    }
}

int ResolverStarted(void*, void*, void* argument) noexcept {
    auto& transfer = *static_cast<Transfer*>(argument);
    transfer.resolving = true;
    transfer.resolveStarted = std::chrono::steady_clock::now();
    curl_easy_getinfo(transfer.easy, CURLINFO_NAMELOOKUP_TIME_T, &transfer.lookupBaseline);
    if (!transfer.retrying) transfer.resolveRetries = 0;
    transfer.retrying = false;
    return 0;
}

int SendStarted(void* argument, char*, char*, int, int) noexcept {
    auto& transfer = *static_cast<Transfer*>(argument);
    transfer.resolving = false;
    transfer.sending = true;
    transfer.sent = false;
    transfer.sendStarted = std::chrono::steady_clock::now();
    curl_easy_getinfo(transfer.easy, CURLINFO_POSTTRANSFER_TIME_T, &transfer.sendBaseline);
    return CURL_PREREQFUNC_OK;
}

int RetryResolve(Object& request) {
    auto& transfer = *request.transfer;
    if (transfer.resolveRetries >= request.settings.resolveRetry) return transfer.error = ERROR_NETWORK;
    ++transfer.resolveRetries;
    if (curl_multi_remove_handle(transfer.multi, transfer.easy) != CURLM_OK) return transfer.error = ERROR_NETWORK;
    transfer.attached = false;
    transfer.resolving = false;
    transfer.sending = false;
    transfer.sent = false;
    transfer.done = false;
    transfer.nativeError = 0;
    transfer.error = 0;
    transfer.retrying = true;
    if (curl_multi_add_handle(transfer.multi, transfer.easy) != CURLM_OK) return transfer.error = ERROR_NETWORK;
    transfer.attached = true;
    return 0;
}

int Pump(Object& request) {
    TransferScope scope(request);
    auto& transfer = *request.transfer;
    if (request.aborted) return transfer.error = ERROR_ABORTED;
    if (transfer.tunnel) {
        if (transfer.done || transfer.consumed < transfer.body.size()) return transfer.error;
        transfer.body.resize(CURL_MAX_WRITE_SIZE);
        std::size_t size = 0;
        const auto result = curl_easy_recv(transfer.easy, transfer.body.data(), transfer.body.size(), &size);
        transfer.body.resize(size);
        transfer.consumed = 0;
        if (result != CURLE_OK && result != CURLE_AGAIN) {
            transfer.nativeError = result;
            return transfer.error = ERROR_NETWORK;
        }
        if (result == CURLE_OK && !size) transfer.done = true;
        return transfer.error;
    }
    int running = 0;
    if (curl_multi_perform(transfer.multi, &running) != CURLM_OK) return transfer.error = ERROR_NETWORK;
    if (request.aborted) return transfer.error = ERROR_ABORTED;
    if (transfer.callbackError) {
        transfer.error = ERROR_NETWORK;
        return transfer.error;
    }
    int remaining = 0;
    while (auto* message = curl_multi_info_read(transfer.multi, &remaining)) {
        if (message->msg == CURLMSG_DONE) {
            transfer.done = true;
            transfer.nativeError = message->data.result;
            if (message->data.result == CURLE_COULDNT_RESOLVE_HOST || message->data.result == CURLE_COULDNT_RESOLVE_PROXY)
                return RetryResolve(request);
            if (message->data.result != CURLE_OK && !transfer.error) transfer.error = ERROR_NETWORK;
            if (!request.proxy.empty() && !transfer.error) {
                transfer.tunnel = true;
                transfer.done = false;
                transfer.sent = true;
            }
        }
    }
    const auto now = std::chrono::steady_clock::now();
    if (transfer.resolving) {
        curl_off_t elapsed = 0;
        curl_easy_getinfo(transfer.easy, CURLINFO_NAMELOOKUP_TIME_T, &elapsed);
        if (elapsed > transfer.lookupBaseline) transfer.resolving = false;
        else if (now - transfer.resolveStarted >= std::chrono::microseconds(request.settings.resolveTimeout)) {
            transfer.nativeError = CURLE_OPERATION_TIMEDOUT;
            return RetryResolve(request);
        }
    }
    if (transfer.sending) {
        curl_off_t elapsed = 0;
        curl_easy_getinfo(transfer.easy, CURLINFO_POSTTRANSFER_TIME_T, &elapsed);
        if (elapsed > transfer.sendBaseline || transfer.ready) {
            transfer.sending = false;
            transfer.sent = true;
        } else if (now - transfer.sendStarted >= std::chrono::microseconds(request.settings.sendTimeout)) {
            transfer.nativeError = CURLE_OPERATION_TIMEDOUT;
            return transfer.error = ERROR_NETWORK;
        }
    }
    return transfer.error;
}

void Notify(Object& request, std::uint32_t events) {
    if (request.settings.epoll)
        request.settings.epoll->Notify({events, events, request.id, request.settings.epollArgument}, request.eventAlive);
}

void RunAsync(Object& request) noexcept {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::microseconds(request.settings.receiveTimeout);
    bool headers = false;
    bool body = false;
    try {
        for (;;) {
            {
                std::lock_guard lock(request.mutex);
                auto& transfer = *request.transfer;
                if (request.aborted) transfer.error = ERROR_ABORTED;
                if (transfer.error) {
                    Notify(request, transfer.error == ERROR_ABORTED ? 0x10U : 0x08U);
                    return;
                }
                if (transfer.consumed < transfer.body.size()) {
                    deadline = std::chrono::steady_clock::now() + std::chrono::microseconds(request.settings.receiveTimeout);
                } else {
                    body = false;
                    if (transfer.paused) {
                        transfer.paused = false;
                        if (curl_easy_pause(transfer.easy, CURLPAUSE_CONT) != CURLE_OK) transfer.error = ERROR_NETWORK;
                    }
                    if (!transfer.error) Pump(request);
                    if (!transfer.sent) deadline = std::chrono::steady_clock::now() + std::chrono::microseconds(request.settings.receiveTimeout);
                    if (!transfer.done && std::chrono::steady_clock::now() >= deadline) transfer.error = ERROR_NETWORK;
                }
                if (transfer.ready && !headers) {
                    headers = true;
                    Notify(request, 2);
                }
                if (transfer.consumed < transfer.body.size() && !body) {
                    body = true;
                    Notify(request, 1);
                }
                if (transfer.error) {
                    Notify(request, transfer.error == ERROR_ABORTED ? 0x10U : 0x08U);
                    return;
                }
                if (transfer.done) {
                    Notify(request, 1);
                    return;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    } catch (...) {
        std::lock_guard lock(request.mutex);
        request.transfer->error = ERROR_OUT_OF_MEMORY;
        Notify(request, 8);
    }
}

int Drive(Object& request, bool headers) {
    auto& transfer = *request.transfer;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::microseconds(request.settings.receiveTimeout);
    for (;;) {
        if (const int error = Pump(request)) return error;
        if ((headers && transfer.ready) || (!headers && transfer.consumed < transfer.body.size()) || transfer.done) return 0;
        const auto now = std::chrono::steady_clock::now();
        if (!transfer.sent) deadline = now + std::chrono::microseconds(request.settings.receiveTimeout);
        if (now >= deadline) return transfer.error = ERROR_NETWORK;
        const auto wait = std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count();
        if (curl_multi_poll(transfer.multi, nullptr, 0, static_cast<int>(std::min<std::int64_t>(wait, 10)), nullptr) != CURLM_OK)
            return transfer.error = ERROR_NETWORK;
    }
}

int Delete(int id, Kind kind) {
    if (InCallback(id)) return ERROR_HTTP_BUSY;
    std::shared_ptr<Object> object;
    {
        std::lock_guard lock(registryMutex);
        const auto found = registry.find(id);
        if (found == registry.end() || found->second->kind != kind) return ERROR_INVALID_ID;
        if (found->second->callbacks) return ERROR_HTTP_BUSY;
        for (const auto& [childId, child] : registry)
            if (child->parent == id) return ERROR_HTTP_BUSY;
        object = std::move(found->second);
        object->aborted = true;
        registry.erase(found);
    }
    {
        std::lock_guard lock(object->mutex);
        *object->eventAlive = false;
    }
    HttpForgetCallback_nid_no_patch(id);
    return 0;
}

template<typename TFunction>
int Configure(int id, TFunction function) {
    auto object = FindAny(id);
    if (!object) return ERROR_INVALID_ID;
    std::lock_guard lock(object->mutex);
    if (object->transfer) return ERROR_INVALID_VALUE;
    return function(*object);
}

}

extern "C" int HttpSetPeerHostname_nid_no_patch(mbedtls_ssl_context* context, const char* hostname) {
    if (!activeRequest || (activeRequest->settings.verify & 0x80)) return __real_mbedtls_ssl_set_hostname(context, hostname);
    try {
        activeRequest->transfer->peerHostname = hostname ? hostname : "";
    } catch (const std::bad_alloc&) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    return __real_mbedtls_ssl_set_hostname(context, nullptr);
}

void HttpContextStarted_nid_no_patch(int id, int sslContext) {
    if (!InitializeCurl()) throw std::runtime_error("HTTP backend initialization failed");
    auto object = std::make_shared<Object>(Kind::Context);
    object->cookieStore = std::make_shared<CookieStore>();
    object->context = id;
    object->sslContext = sslContext;
    object->id = id;
    std::lock_guard lock(registryMutex);
    registry.emplace(id, std::move(object));
}

bool HttpHasObject_nid_no_patch(int id) { return FindAny(id) != nullptr; }
bool HttpInCallbackContext_nid_no_patch(int id) {
    const auto context = Find(id, Kind::Context);
    return context && context->callbacks.load() != 0;
}

int HttpBindEpoll_nid_no_patch(int id, std::shared_ptr<HttpEventSink> sink, HttpEpollHandle handle, void* argument) {
    auto object = FindAny(id);
    if (!object || object->kind == Kind::Context) return ERROR_INVALID_ID;
    if (sink && sink->Context() != object->context) return ERROR_INVALID_ID;
    std::lock_guard lock(object->mutex);
    *object->eventAlive = false;
    object->eventAlive = std::make_shared<std::atomic<bool>>(true);
    object->settings.epoll = std::move(sink);
    object->settings.epollHandle = handle;
    object->settings.epollArgument = argument;
    if (object->transfer && object->transfer->ready) Notify(*object, 2);
    if (object->transfer && (object->transfer->done || object->transfer->consumed < object->transfer->body.size())) Notify(*object, 1);
    return 0;
}

int HttpGetEpoll_nid_no_patch(int id, HttpEpollHandle* handle, void** argument) {
    if (!handle) return ERROR_INVALID_VALUE;
    auto object = FindAny(id);
    if (!object || object->kind == Kind::Context) return ERROR_INVALID_ID;
    std::lock_guard lock(object->mutex);
    *handle = object->settings.epollHandle;
    if (argument) *argument = object->settings.epollArgument;
    return 0;
}

void HttpContextStopped_nid_no_patch(int id) {
    std::vector<std::shared_ptr<Object>> removed;
    {
        std::lock_guard lock(registryMutex);
        for (auto it = registry.begin(); it != registry.end();) {
            if (it->second->context == id) {
                it->second->aborted = true;
                removed.push_back(std::move(it->second));
                HttpForgetCallback_nid_no_patch(it->first);
                it = registry.erase(it);
            } else ++it;
        }
    }
    for (const auto& object : removed) {
        std::lock_guard lock(object->mutex);
        *object->eventAlive = false;
    }
}

extern "C" {

int APS5_VABI sceHttpCreateTemplate(int context, const char* agent, int version, int proxy) {
    auto parent = Find(context, Kind::Context);
    if (!parent) return ERROR_INVALID_ID;
    if ((version != 1 && version != 2) || !agent || !Field(agent)) return ERROR_INVALID_VALUE;
    if (proxy != 0 && proxy != 1) return ERROR_INVALID_VALUE;
    auto object = std::make_shared<Object>(Kind::Template);
    std::lock_guard lock(parent->mutex);
    object->settings = parent->settings;
    object->settings.agent = agent;
    object->settings.version = version == 1 ? CURL_HTTP_VERSION_1_0 : CURL_HTTP_VERSION_1_1;
    object->settings.autoProxy = proxy != 0;
    object->parent = context;
    object->context = context;
    return Insert(std::move(object));
}

int APS5_VABI sceHttpCreateConnectionWithURL(int parentId, const char* url, int keepAlive) {
    auto parent = Find(parentId, Kind::Template);
    if (!parent) return ERROR_INVALID_ID;
    if (keepAlive != 0 && keepAlive != 1) return ERROR_INVALID_VALUE;
    const auto normalized = NormalizeUrl(url, true);
    if (normalized.empty()) return ERROR_INVALID_URL;
    auto object = std::make_shared<Object>(Kind::Connection);
    std::lock_guard lock(parent->mutex);
    object->settings = parent->settings;
    object->settings.keepAlive = keepAlive != 0;
    object->context = parent->context;
    object->parent = parentId;
    object->url = normalized;
    return Insert(std::move(object));
}

int APS5_VABI sceHttpCreateConnection(int parent, const char* server, const char* scheme, std::uint16_t port, int keepAlive) {
    if (!server || !scheme) return ERROR_INVALID_URL;
    std::string host(server);
    if (host.find(':') != std::string::npos && !host.starts_with('[')) host = '[' + host + ']';
    const auto url = std::string(scheme) + "://" + host + (port ? ':' + std::to_string(port) : std::string()) + '/';
    return sceHttpCreateConnectionWithURL(parent, url.c_str(), keepAlive);
}

int APS5_VABI sceHttpCreateRequest2(int parent, const char* method, const char* path, std::uint64_t length) {
    return NewRequest(parent, method, path, length, false);
}
int APS5_VABI sceHttpCreateRequestWithURL2(int parent, const char* method, const char* url, std::uint64_t length) {
    return NewRequest(parent, method, url, length, true);
}
int APS5_VABI sceHttpCreateRequest(int parent, int method, const char* path, std::uint64_t length) {
    return Method(method) ? NewRequest(parent, Method(method), path, length, false) : ERROR_INVALID_VALUE;
}
int APS5_VABI sceHttpCreateRequestWithURL(int parent, int method, const char* url, std::uint64_t length) {
    return Method(method) ? NewRequest(parent, Method(method), url, length, true) : ERROR_INVALID_VALUE;
}
int APS5_VABI sceHttpDeleteTemplate(int id) { return Delete(id, Kind::Template); }
int APS5_VABI sceHttpDeleteConnection(int id) { return Delete(id, Kind::Connection); }
int APS5_VABI sceHttpDeleteRequest(int id) { return Delete(id, Kind::Request); }

int APS5_VABI sceHttpAddRequestHeader(int id, const char* name, const char* value, std::uint32_t mode) {
    if (!name || !value || !Token(name) || !Field(value) || mode > 1) return ERROR_INVALID_VALUE;
    return Configure(id, [&](Object& object) {
        auto& headers = object.settings.headers;
        if (mode == 0) std::erase_if(headers, [&](const auto& header) { return EqualName(header.first, name); });
        headers.emplace_back(name, value);
        return 0;
    });
}

int APS5_VABI sceHttpSetConnectTimeOut(int id, std::uint32_t usec) {
    if (!usec) return ERROR_INVALID_VALUE;
    return Configure(id, [&](Object& object) { object.settings.connectTimeout = usec; return 0; });
}
int APS5_VABI sceHttpSetRecvTimeOut(int id, std::uint32_t usec) {
    if (!usec) return ERROR_INVALID_VALUE;
    return Configure(id, [&](Object& object) { object.settings.receiveTimeout = usec; return 0; });
}
int APS5_VABI sceHttpSetResolveTimeOut(int id, std::uint32_t usec) {
    if (!usec) return ERROR_INVALID_VALUE;
    return Configure(id, [&](Object& object) { object.settings.resolveTimeout = usec; return 0; });
}
int APS5_VABI sceHttpSetSendTimeOut(int id, std::uint32_t usec) {
    if (!usec) return ERROR_INVALID_VALUE;
    return Configure(id, [&](Object& object) { object.settings.sendTimeout = usec; return 0; });
}
int APS5_VABI sceHttpSetResolveRetry(int id, std::int32_t retry) {
    if (retry < 0) return ERROR_INVALID_VALUE;
    return Configure(id, [&](Object& object) { object.settings.resolveRetry = retry; return 0; });
}
int APS5_VABI sceHttpSetResponseHeaderMaxSize(int id, std::uint64_t size) {
    if (!size || size > SIZE_MAX) return ERROR_INVALID_VALUE;
    return Configure(id, [&](Object& object) { object.settings.headerLimit = static_cast<std::size_t>(size); return 0; });
}
int APS5_VABI sceHttpSetRecvBlockSize(int id, std::uint32_t size) {
    if (!size) return ERROR_INVALID_VALUE;
    return Configure(id, [&](Object& object) { object.settings.readBlock = size; return 0; });
}
int APS5_VABI sceHttpSetRequestContentLength(int id, std::uint64_t length) {
    return Configure(id, [&](Object& object) {
        if (object.kind != Kind::Request) return ERROR_INVALID_ID;
        object.contentLength = length;
        return 0;
    });
}
int APS5_VABI sceHttpSetNonblock(int id, int enabled) {
    if (enabled != 0 && enabled != 1) return ERROR_INVALID_VALUE;
    return Configure(id, [&](Object& object) { object.settings.nonblock = enabled != 0; return 0; });
}
int APS5_VABI sceHttpGetNonblock(int id, int* enabled) {
    if (!enabled) return ERROR_INVALID_VALUE;
    auto object = FindAny(id);
    if (!object) return ERROR_INVALID_ID;
    std::lock_guard lock(object->mutex);
    *enabled = object->settings.nonblock;
    return 0;
}
int APS5_VABI sceHttpTrySetNonblock(int id, int enabled) {
    auto object = FindAny(id);
    if (!object) return ERROR_INVALID_ID;
    if (enabled != 0 && enabled != 1) return ERROR_INVALID_VALUE;
    std::unique_lock lock(object->mutex, std::try_to_lock);
    if (!lock.owns_lock()) return ERROR_HTTP_BUSY;
    if (object->transfer) return ERROR_INVALID_VALUE;
    object->settings.nonblock = enabled != 0;
    return 0;
}
int APS5_VABI sceHttpTryGetNonblock(int id, int* enabled) {
    if (!enabled) return ERROR_INVALID_VALUE;
    auto object = FindAny(id);
    if (!object) return ERROR_INVALID_ID;
    std::unique_lock lock(object->mutex, std::try_to_lock);
    if (!lock.owns_lock()) return ERROR_HTTP_BUSY;
    *enabled = object->settings.nonblock;
    return 0;
}
int APS5_VABI sceHttpSetAutoRedirect(int id, int enabled) {
    if (enabled != 0 && enabled != 1) return ERROR_INVALID_VALUE;
    return Configure(id, [&](Object& object) { object.settings.redirect = enabled; return 0; });
}

int APS5_VABI sceHttpSetCookieEnabled(int id, int enabled) {
    if (enabled != 0 && enabled != 1) return ERROR_INVALID_VALUE;
    return Configure(id, [&](Object& object) { object.settings.cookies = enabled; return 0; });
}

int APS5_VABI sceHttpSetInflateGZIPEnabled(int id, int enabled) {
    if (enabled != 0 && enabled != 1) return ERROR_INVALID_VALUE;
    return Configure(id, [&](Object& object) { object.settings.inflate = enabled; return 0; });
}

int APS5_VABI sceHttpSetChunkedTransferEnabled(int id, int enabled) {
    if (enabled != 0 && enabled != 1) return ERROR_INVALID_VALUE;
    return Configure(id, [&](Object& object) { object.settings.chunked = enabled; return 0; });
}

int APS5_VABI sceHttpsEnableOption(int id, std::uint32_t flags) {
    if (flags & ~0xfdU) NotImplemented_nid_no_patch(__func__);
    return Configure(id, [&](Object& object) { object.settings.verify |= flags; return 0; });
}

int APS5_VABI sceHttpsDisableOption(int id, std::uint32_t flags) {
    if (flags & ~0xfdU) NotImplemented_nid_no_patch(__func__);
    return Configure(id, [&](Object& object) { object.settings.verify &= ~flags; return 0; });
}

int APS5_VABI sceHttpsSetMinSslVersion(int id, std::uint32_t version) {
    if (version > 5) return ERROR_INVALID_VALUE;
    return Configure(id, [&](Object& object) { object.settings.minimumTlsVersion = version; return 0; });
}

int APS5_VABI sceHttpsSetSslCallback(int id, HttpsCallback callback, void* argument) {
    return Configure(id, [&](Object& object) {
        const int context = object.kind == Kind::Context ? object.sslContext : object.root->sslContext;
        if (callback && !SslContextExists_nid_no_patch(context)) return ERROR_INVALID_ID;
        object.settings.sslCallback = callback;
        object.settings.sslArgument = argument;
        return 0;
    });
}

int APS5_VABI sceHttpsSetSslVersion(int id, int version) {
    if (version < 0 || version > 5) return ERROR_INVALID_VALUE;
    return Configure(id, [&](Object& object) {
        object.settings.tlsVersion = static_cast<std::uint32_t>(version);
        return 0;
    });
}

int APS5_VABI sceHttpsLoadCert(int id, int count, SceSsl::Data** authorities, SceSsl::Data* certificate, SceSsl::Data* key) {
    if (count < 0 || (count && !authorities) || (!!certificate != !!key)) return ERROR_INVALID_VALUE;
    auto context = Find(id, Kind::Context);
    if (!context) return ERROR_INVALID_ID;
    const auto copy = [](const SceSsl::Data* data) {
        if (!data || !data->ptr || !data->size || data->size > INT_MAX) return std::vector<unsigned char>{};
        std::vector<unsigned char> bytes(data->ptr, data->ptr + data->size);
        if (bytes.front() != 0x30 && bytes.back() != 0) bytes.push_back(0);
        return bytes;
    };
    std::string pem;
    for (int index = 0; index < count; ++index) {
        const auto bytes = copy(authorities[index]);
        if (bytes.empty()) return ERROR_INVALID_VALUE;
        ParsedCertificate chain;
        if (mbedtls_x509_crt_parse(&chain.value, bytes.data(), bytes.size()) != 0) return ERROR_INVALID_VALUE;
        for (auto* entry = &chain.value; entry && entry->raw.p; entry = entry->next) {
            std::size_t length = 0;
            mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n",
                entry->raw.p, entry->raw.len, nullptr, 0, &length);
            std::vector<unsigned char> encoded(length);
            if (mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n",
                entry->raw.p, entry->raw.len, encoded.data(), encoded.size(), &length) != 0) return ERROR_INVALID_VALUE;
            pem.append(reinterpret_cast<char*>(encoded.data()), length - 1);
        }
    }
    auto certBytes = certificate ? copy(certificate) : std::vector<unsigned char>{};
    auto keyBytes = key ? copy(key) : std::vector<unsigned char>{};
    if (certificate) {
        if (certBytes.empty() || keyBytes.empty()) return ERROR_INVALID_VALUE;
        ParsedCertificate parsed;
        if (mbedtls_x509_crt_parse(&parsed.value, certBytes.data(), certBytes.size()) != 0) return ERROR_INVALID_VALUE;
        mbedtls_pk_context privateKey;
        mbedtls_pk_init(&privateKey);
        mbedtls_entropy_context entropy;
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_context random;
        mbedtls_ctr_drbg_init(&random);
        int result = mbedtls_ctr_drbg_seed(&random, mbedtls_entropy_func, &entropy, nullptr, 0);
        if (!result) result = mbedtls_pk_parse_key(&privateKey, keyBytes.data(), keyBytes.size(), nullptr, 0,
            mbedtls_ctr_drbg_random, &random);
        if (!result) result = mbedtls_pk_check_pair(&parsed.value.pk, &privateKey, mbedtls_ctr_drbg_random, &random);
        mbedtls_pk_free(&privateKey);
        mbedtls_ctr_drbg_free(&random);
        mbedtls_entropy_free(&entropy);
        if (result) return ERROR_INVALID_VALUE;
    }
    std::lock_guard lock(context->mutex);
    context->settings.authorities += pem;
    if (certificate) {
        if (!context->settings.key.empty()) mbedtls_platform_zeroize(context->settings.key.data(), context->settings.key.size());
        context->settings.certificate = std::move(certBytes);
        context->settings.key = std::move(keyBytes);
    }
    return 0;
}

int APS5_VABI sceHttpsUnloadCert(int id) {
    if (!Find(id, Kind::Context)) return ERROR_INVALID_ID;
    return Configure(id, [](Object& object) {
        object.settings.authorities.clear();
        object.settings.certificate.clear();
        if (!object.settings.key.empty()) mbedtls_platform_zeroize(object.settings.key.data(), object.settings.key.size());
        object.settings.key.clear();
        return 0;
    });
}

int APS5_VABI sceHttpsGetCaList(int id, SceSsl::CaList* output) {
    if (!output) return ERROR_INVALID_VALUE;
    auto context = Find(id, Kind::Context);
    if (!context) return ERROR_INVALID_ID;
    std::lock_guard lock(context->mutex);
    if (context->settings.authorities.empty()) {
        *output = {};
        return 0;
    }
    SceSsl::Data input{reinterpret_cast<std::uint8_t*>(context->settings.authorities.data()), context->settings.authorities.size() + 1};
    SceSsl::CaList list{};
    try {
        if (SslImportCaList_nid_no_patch(context->sslContext, &input, &list) != 0) return ERROR_INVALID_VALUE;
        context->caLists.emplace(list.certs, list);
    } catch (const std::bad_alloc&) {
        if (list.certs) SslReleaseCaList_nid_no_patch(context->sslContext, list);
        return ERROR_OUT_OF_MEMORY;
    } catch (const std::invalid_argument&) {
        return ERROR_INVALID_ID;
    }
    *output = list;
    return 0;
}

int APS5_VABI sceHttpsFreeCaList(int id, SceSsl::CaList* list) {
    if (!list) return ERROR_INVALID_VALUE;
    auto context = Find(id, Kind::Context);
    if (!context) return ERROR_INVALID_ID;
    std::lock_guard lock(context->mutex);
    if (!list->certs && !list->num) return 0;
    const auto found = context->caLists.find(list->certs);
    if (found == context->caLists.end() || found->second.num != list->num) return ERROR_INVALID_VALUE;
    SslReleaseCaList_nid_no_patch(context->sslContext, *list);
    context->caLists.erase(found);
    *list = {};
    return 0;
}

int APS5_VABI sceHttpsGetSslError(int id, int* error, std::uint32_t* detail) {
    if (!error || !detail) return ERROR_INVALID_VALUE;
    auto request = Find(id, Kind::Request);
    if (!request) return ERROR_INVALID_ID;
    std::lock_guard lock(request->mutex);
    *error = 0;
    *detail = 0;
    if (!request->transfer) return 0;
    const auto& transfer = *request->transfer;
    if (transfer.callbackError) {
        *error = static_cast<int>(0x80435063);
        *detail = 1;
        return 0;
    }
    *detail = VerificationBits(transfer.verifyError);
    if (*detail) *error = static_cast<int>(0x80435060);
    switch (transfer.nativeError) {
    case CURLE_PEER_FAILED_VERIFICATION:
    case CURLE_SSL_CERTPROBLEM:
    case CURLE_SSL_CACERT_BADFILE:
    case CURLE_SSL_CRL_BADFILE:
    case CURLE_SSL_ISSUER_ERROR:
    case CURLE_SSL_PINNEDPUBKEYNOTMATCH:
    case CURLE_SSL_INVALIDCERTSTATUS:
    case CURLE_SSL_CLIENTCERT:
        *error = static_cast<int>(0x80435060);
        if (!*detail) *detail = 2;
        break;
    case CURLE_SSL_CONNECT_ERROR:
    case CURLE_SSL_CIPHER:
    case CURLE_USE_SSL_FAILED:
        if (!*error) *error = static_cast<int>(0x80435061);
        if (!*detail) *detail = 1;
        break;
    case CURLE_SSL_ENGINE_NOTFOUND:
    case CURLE_SSL_ENGINE_SETFAILED:
    case CURLE_SSL_ENGINE_INITFAILED:
        *error = static_cast<int>(0x80435063);
        *detail |= 1;
        break;
    case CURLE_SEND_ERROR:
    case CURLE_RECV_ERROR:
    case CURLE_SSL_SHUTDOWN_FAILED: {
        curl_off_t connected = 0;
        curl_easy_getinfo(transfer.easy, CURLINFO_APPCONNECT_TIME_T, &connected);
        if (connected && (request->url.starts_with("https:") || request->proxy.starts_with("https:"))) {
            *error = static_cast<int>(0x80435062);
            *detail |= 1;
        }
        break;
    }
    default:
        break;
    }
    long proxyStatus = 0;
    curl_easy_getinfo(transfer.easy, CURLINFO_HTTP_CONNECTCODE, &proxyStatus);
    if (proxyStatus >= 300 && (request->url.starts_with("https:") || request->proxy.starts_with("https:"))) {
        *error = static_cast<int>(0x80435064);
        *detail = 0;
    }
    return 0;
}

int APS5_VABI sceHttpSendRequest(int id, const void* data, std::size_t size) {
    if (InCallback(id)) return ERROR_HTTP_BUSY;
    auto request = Find(id, Kind::Request);
    if (!request) return ERROR_INVALID_ID;
    std::lock_guard lock(request->mutex);
    if (request->aborted) return ERROR_ABORTED;
    if (request->transfer) return ERROR_INVALID_VALUE;
    if ((!data && size) || size > INT64_MAX) return ERROR_INVALID_VALUE;
    bool chunked = request->settings.chunked;
    bool length = false;
    std::string encoding;
    if (const int error = Framing(*request, size, chunked, length, encoding)) return error;
    if (!request->proxy.empty() && (size || chunked)) return ERROR_INVALID_VALUE;
    std::string proxy = request->proxy;
    if (proxy.empty() && request->settings.autoProxy) {
        if (const int error = ProxyConfiguration(proxy)) return error;
    }
    {
        std::lock_guard contextLock(request->root->mutex);
        request->settings.authorities = request->root->settings.authorities;
        request->settings.certificate = request->root->settings.certificate;
        if (!request->settings.key.empty()) mbedtls_platform_zeroize(request->settings.key.data(), request->settings.key.size());
        request->settings.key = request->root->settings.key;
    }
    if (HasCallbacks(id)) NotImplemented_nid_no_patch(__func__);
    if ((request->method == "GET" || request->method == "HEAD") && size) return ERROR_INVALID_VALUE;
    if (!InitializeCurl()) return ERROR_NETWORK;
    request->transfer = std::make_unique<Transfer>();
    auto& transfer = *request->transfer;
    if (!transfer.easy || !transfer.multi) return transfer.error = ERROR_OUT_OF_MEMORY;
    transfer.headerLimit = request->settings.headerLimit;
    transfer.redirect = request->settings.redirect;
    const auto set = [&](CURLoption option, auto value) {
        if (curl_easy_setopt(transfer.easy, option, value) != CURLE_OK) throw std::runtime_error("HTTP curl option configuration failed");
    };
    set(CURLOPT_URL, request->url.c_str());
    set(CURLOPT_PROTOCOLS_STR, "http,https");
    set(CURLOPT_REDIR_PROTOCOLS_STR, request->url.starts_with("https:") ? "https" : "http,https");
    set(CURLOPT_FOLLOWLOCATION, request->settings.redirect ? CURLFOLLOW_OBEYCODE : 0L);
    set(CURLOPT_MAXREDIRS, 10L);
    set(CURLOPT_SSL_VERIFYPEER, (request->settings.verify & 1) ? 1L : 0L);
    set(CURLOPT_SSL_VERIFYHOST, (request->settings.verify & 4) ? 2L : 0L);
    constexpr long minimumVersions[] = {CURL_SSLVERSION_DEFAULT, CURL_SSLVERSION_SSLv2, CURL_SSLVERSION_SSLv3,
        CURL_SSLVERSION_TLSv1_0, CURL_SSLVERSION_TLSv1_1, CURL_SSLVERSION_TLSv1_2};
    const long minimum = std::max<long>(CURL_SSLVERSION_TLSv1_2, minimumVersions[request->settings.minimumTlsVersion]);
    const long tlsVersion = std::max(minimum, minimumVersions[request->settings.tlsVersion]);
    set(CURLOPT_SSLVERSION, tlsVersion);
    set(CURLOPT_PROXY_SSL_VERIFYPEER, (request->settings.verify & 1) ? 1L : 0L);
    set(CURLOPT_PROXY_SSL_VERIFYHOST, (request->settings.verify & 4) ? 2L : 0L);
    set(CURLOPT_PROXY_SSLVERSION, tlsVersion);
    set(CURLOPT_SSL_SESSIONID_CACHE, (request->settings.verify & 0x40) ? 1L : 0L);
    set(CURLOPT_SSL_CTX_FUNCTION, ConfigureTls);
    set(CURLOPT_SSL_CTX_DATA, request.get());
    if (!request->settings.authorities.empty()) {
        curl_blob blob{request->settings.authorities.data(), request->settings.authorities.size() + 1, CURL_BLOB_COPY};
        set(CURLOPT_CAINFO_BLOB, &blob);
        set(CURLOPT_PROXY_CAINFO_BLOB, &blob);
    }
    if (!request->settings.certificate.empty()) {
        curl_blob cert{request->settings.certificate.data(), request->settings.certificate.size(), CURL_BLOB_COPY};
        curl_blob key{request->settings.key.data(), request->settings.key.size(), CURL_BLOB_COPY};
        set(CURLOPT_SSLCERTTYPE, request->settings.certificate.front() == 0x30 ? "DER" : "PEM");
        set(CURLOPT_SSLKEYTYPE, request->settings.key.front() == 0x30 ? "DER" : "PEM");
        set(CURLOPT_SSLCERT_BLOB, &cert);
        set(CURLOPT_SSLKEY_BLOB, &key);
        set(CURLOPT_PROXY_SSLCERTTYPE, request->settings.certificate.front() == 0x30 ? "DER" : "PEM");
        set(CURLOPT_PROXY_SSLKEYTYPE, request->settings.key.front() == 0x30 ? "DER" : "PEM");
        set(CURLOPT_PROXY_SSLCERT_BLOB, &cert);
        set(CURLOPT_PROXY_SSLKEY_BLOB, &key);
    }
    if (request->settings.cookies) {
        set(CURLOPT_SHARE, request->cookieStore->share);
        set(CURLOPT_COOKIEFILE, "");
    }
    if (request->settings.inflate) set(CURLOPT_ACCEPT_ENCODING, "gzip,deflate");
    set(CURLOPT_PROXY, proxy.c_str());
    set(CURLOPT_NOPROXY, "");
    if (!request->proxy.empty()) {
        set(CURLOPT_HTTPPROXYTUNNEL, 1L);
        set(CURLOPT_CONNECT_ONLY, 1L);
    }
    set(CURLOPT_NOSIGNAL, 1L);
    set(CURLOPT_FORBID_REUSE, request->settings.keepAlive || !request->proxy.empty() ? 0L : 1L);
    set(CURLOPT_HTTP_VERSION, request->settings.version);
    set(CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>((std::uint64_t{request->settings.connectTimeout} + 999) / 1000));
    set(CURLOPT_USERAGENT, request->settings.agent.c_str());
    set(CURLOPT_HEADERFUNCTION, Header);
    set(CURLOPT_HEADERDATA, &transfer);
    set(CURLOPT_WRITEFUNCTION, Body);
    set(CURLOPT_WRITEDATA, &transfer);
    set(CURLOPT_RESOLVER_START_FUNCTION, ResolverStarted);
    set(CURLOPT_RESOLVER_START_DATA, &transfer);
    set(CURLOPT_DNS_CACHE_TIMEOUT, 0L);
    set(CURLOPT_PREREQFUNCTION, SendStarted);
    set(CURLOPT_PREREQDATA, &transfer);
    set(CURLOPT_CUSTOMREQUEST, request->method.c_str());
    if (request->method == "HEAD") set(CURLOPT_NOBODY, 1L);
    else if (size || chunked || request->method == "POST" || request->method == "PUT") {
        set(CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(size));
        set(CURLOPT_COPYPOSTFIELDS, size ? data : "");
    }
    const auto append = [&](const std::string& line) {
        auto* next = curl_slist_append(transfer.outgoing, line.c_str());
        if (!next) throw std::bad_alloc();
        transfer.outgoing = next;
    };
    append("Expect:");
    if (chunked) append("Transfer-Encoding: " + (encoding.empty() ? std::string("chunked") : encoding));
    if (length) append("Content-Length: " + std::to_string(size));
    if (!request->settings.keepAlive && request->proxy.empty()) append("Connection: close");
    for (const auto& [name, value] : request->settings.headers) {
        if (EqualName(name, "Content-Length") || EqualName(name, "Transfer-Encoding")) continue;
        append(name + (value.empty() ? ";" : ": " + value));
    }
    set(CURLOPT_HTTPHEADER, transfer.outgoing);
    if (!request->proxy.empty()) set(CURLOPT_PROXYHEADER, transfer.outgoing);
    if (curl_multi_add_handle(transfer.multi, transfer.easy) != CURLM_OK) return transfer.error = ERROR_NETWORK;
    transfer.attached = true;
    if (request->settings.nonblock) {
        request->worker = std::jthread([object = request.get()] { RunAsync(*object); });
        return 0;
    }
    const int error = Drive(*request, true);
    return error ? error : transfer.ready ? 0 : ERROR_NETWORK;
}

int APS5_VABI sceHttpReadData(int id, void* output, std::size_t size) {
    if (InCallback(id)) return ERROR_HTTP_BUSY;
    auto request = Find(id, Kind::Request);
    if (!request) return ERROR_INVALID_ID;
    if (!output && size) return ERROR_INVALID_VALUE;
    std::lock_guard lock(request->mutex);
    if (request->aborted) return ERROR_ABORTED;
    if (!request->transfer) return ERROR_NETWORK;
    auto& transfer = *request->transfer;
    if (transfer.error) return transfer.error;
    if (!size) return 0;
    if (request->settings.nonblock && transfer.consumed == transfer.body.size()) return transfer.done ? 0 : ERROR_AGAIN;
    if (transfer.consumed == transfer.body.size() && !transfer.done) {
        transfer.body.clear();
        transfer.consumed = 0;
        transfer.paused = false;
        if (!transfer.tunnel && curl_easy_pause(transfer.easy, CURLPAUSE_CONT) != CURLE_OK) return transfer.error = ERROR_NETWORK;
        if (const int error = Drive(*request, false)) return error;
    }
    const auto count = std::min({size, transfer.body.size() - transfer.consumed, request->settings.readBlock, std::size_t{INT_MAX}});
    if (count) std::memcpy(output, transfer.body.data() + transfer.consumed, count);
    transfer.consumed += count;
    if (request->settings.nonblock && transfer.done && transfer.consumed == transfer.body.size()) Notify(*request, 1);
    return static_cast<int>(count);
}

int APS5_VABI sceHttpAbortRequest(int id) {
    auto request = Find(id, Kind::Request);
    if (!request) return ERROR_INVALID_ID;
    request->aborted = true;
    return 0;
}

int APS5_VABI sceHttpGetStatusCode(int id, int* status) {
    if (!status) return ERROR_INVALID_VALUE;
    auto request = Find(id, Kind::Request);
    if (!request) return ERROR_INVALID_ID;
    std::lock_guard lock(request->mutex);
    if (request->aborted) return ERROR_ABORTED;
    if (request->transfer && request->transfer->error) return request->transfer->error;
    if (!request->transfer || !request->transfer->ready) return request->transfer && request->settings.nonblock ? ERROR_AGAIN : ERROR_NETWORK;
    *status = request->transfer->status;
    return 0;
}

int APS5_VABI sceHttpGetAllResponseHeaders(int id, char** headers, std::size_t* size) {
    if (!headers || !size) return ERROR_INVALID_VALUE;
    auto request = Find(id, Kind::Request);
    if (!request) return ERROR_INVALID_ID;
    std::lock_guard lock(request->mutex);
    if (request->aborted) return ERROR_ABORTED;
    if (request->transfer && request->transfer->error) return request->transfer->error;
    if (!request->transfer || !request->transfer->ready) return request->transfer && request->settings.nonblock ? ERROR_AGAIN : ERROR_NETWORK;
    *headers = request->transfer->headers.data();
    *size = request->transfer->headers.size();
    return 0;
}

int APS5_VABI sceHttpGetResponseContentLength(int id, int* result, std::uint64_t* size) {
    if (!result || !size) return ERROR_INVALID_VALUE;
    auto request = Find(id, Kind::Request);
    if (!request) return ERROR_INVALID_ID;
    std::lock_guard lock(request->mutex);
    if (request->aborted) return ERROR_ABORTED;
    if (request->transfer && request->transfer->error) return request->transfer->error;
    if (!request->transfer || !request->transfer->ready) return request->transfer && request->settings.nonblock ? ERROR_AGAIN : ERROR_NETWORK;
    curl_off_t length = -1;
    if (!request->transfer->tunnel && curl_easy_getinfo(request->transfer->easy, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &length) != CURLE_OK)
        return ERROR_NETWORK;
    *result = length < 0 ? static_cast<int>(0x80431071) : 0;
    *size = length < 0 ? 0 : static_cast<std::uint64_t>(length);
    return 0;
}

int APS5_VABI sceHttpGetLastErrno(int id, int* error) {
    if (!error) return ERROR_INVALID_VALUE;
    auto request = Find(id, Kind::Request);
    if (!request) return ERROR_INVALID_ID;
    std::lock_guard lock(request->mutex);
    long native = 0;
    if (request->transfer) curl_easy_getinfo(request->transfer->easy, CURLINFO_OS_ERRNO, &native);
    *error = static_cast<int>(native);
    return 0;
}

}
