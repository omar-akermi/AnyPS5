#include "Transport.hpp"
#include "HttpErrors.hpp"
#include "prx/libc/include/General.hpp"
#include <curl/curl.h>
#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace {

enum class Kind { Context, Template, Connection, Request };

struct Settings {
    std::string agent;
    long version = CURL_HTTP_VERSION_1_1;
    std::uint32_t connectTimeout = 30000000;
    std::uint32_t receiveTimeout = 30000000;
    std::size_t headerLimit = 16384;
    std::size_t readBlock = INT_MAX;
    bool keepAlive = false;
    std::vector<std::pair<std::string, std::string>> headers;
};

struct Transfer {
    CURL* easy = curl_easy_init();
    CURLM* multi = curl_multi_init();
    curl_slist* outgoing = nullptr;
    bool attached = false;
    bool ready = false;
    bool done = false;
    int status = 0;
    int error = 0;
    int nativeError = 0;
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

struct Object {
    Kind kind;
    int parent = 0;
    int context = 0;
    Settings settings;
    std::string url;
    std::string method;
    std::uint64_t contentLength = 0;
    std::mutex mutex;
    std::atomic<bool> aborted{false};
    std::unique_ptr<Transfer> transfer;

    explicit Object(Kind value) : kind(value) {}
};

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
    const int id = HttpNextHandle_nid_no_patch();
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
    constexpr const char* methods[] = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"};
    return method >= 0 && method < 7 ? methods[method] : nullptr;
}

int NewRequest(int connection, const char* method, const char* location, std::uint64_t length, bool absolute) {
    auto parent = Find(connection, Kind::Connection);
    if (!parent) return ERROR_INVALID_ID;
    if (!method || !location || !Token(method)) return ERROR_INVALID_VALUE;
    if (EqualName(method, "CONNECT")) NotImplemented_nid_no_patch("HTTP CONNECT requests");
    auto request = std::make_shared<Object>(Kind::Request);
    {
        std::lock_guard lock(parent->mutex);
        request->settings = parent->settings;
        request->context = parent->context;
        if (!absolute && location[0] != '/') return ERROR_INVALID_URL;
        const auto url = absolute ? std::string(location) : parent->url.substr(0, parent->url.size() - 1) + location;
        request->url = NormalizeUrl(url.c_str(), false);
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
        if (line == "\r\n" && transfer.status >= 200) transfer.ready = true;
        return length;
    } catch (...) {
        transfer.error = ERROR_OUT_OF_MEMORY;
        return 0;
    }
}

std::size_t Body(char* bytes, std::size_t size, std::size_t count, void* argument) noexcept {
    auto& transfer = *static_cast<Transfer*>(argument);
    if (transfer.consumed != transfer.body.size()) return CURL_WRITEFUNC_PAUSE;
    try {
        transfer.body.assign(bytes, bytes + size * count);
        transfer.consumed = 0;
        return size * count;
    } catch (...) {
        transfer.error = ERROR_OUT_OF_MEMORY;
        return 0;
    }
}

int Drive(Object& request, bool headers) {
    auto& transfer = *request.transfer;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::microseconds(request.settings.receiveTimeout);
    for (;;) {
        if (request.aborted) return transfer.error = ERROR_ABORTED;
        int running = 0;
        if (curl_multi_perform(transfer.multi, &running) != CURLM_OK) return transfer.error = ERROR_NETWORK;
        int remaining = 0;
        while (auto* message = curl_multi_info_read(transfer.multi, &remaining)) {
            if (message->msg == CURLMSG_DONE) {
                transfer.done = true;
                transfer.nativeError = message->data.result;
                if (message->data.result != CURLE_OK && !transfer.error) transfer.error = ERROR_NETWORK;
            }
        }
        if (transfer.error) return transfer.error;
        if ((headers && transfer.ready) || (!headers && transfer.consumed < transfer.body.size()) || transfer.done) return 0;
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return transfer.error = ERROR_NETWORK;
        const auto wait = std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count();
        if (curl_multi_poll(transfer.multi, nullptr, 0, static_cast<int>(std::min<std::int64_t>(wait, 10)), nullptr) != CURLM_OK)
            return transfer.error = ERROR_NETWORK;
    }
}

int Delete(int id, Kind kind) {
    std::shared_ptr<Object> object;
    {
        std::lock_guard lock(registryMutex);
        const auto found = registry.find(id);
        if (found == registry.end() || found->second->kind != kind) return ERROR_INVALID_ID;
        for (const auto& [childId, child] : registry)
            if (child->parent == id) return ERROR_HTTP_BUSY;
        object = std::move(found->second);
        object->aborted = true;
        registry.erase(found);
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

void HttpContextStarted_nid_no_patch(int id) {
    auto object = std::make_shared<Object>(Kind::Context);
    object->context = id;
    std::lock_guard lock(registryMutex);
    registry.emplace(id, std::move(object));
}

bool HttpHasObject_nid_no_patch(int id) { return FindAny(id) != nullptr; }

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
}

extern "C" {

int APS5_VABI sceHttpCreateTemplate(int context, const char* agent, int version, int proxy) {
    auto parent = Find(context, Kind::Context);
    if (!parent) return ERROR_INVALID_ID;
    if ((version != 1 && version != 2) || !agent || !Field(agent)) return ERROR_INVALID_VALUE;
    if (proxy) NotImplemented_nid_no_patch("HTTP automatic proxy configuration");
    auto object = std::make_shared<Object>(Kind::Template);
    std::lock_guard lock(parent->mutex);
    object->settings = parent->settings;
    object->settings.agent = agent;
    object->settings.version = version == 1 ? CURL_HTTP_VERSION_1_0 : CURL_HTTP_VERSION_1_1;
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
    if (EqualName(name, "Content-Length") || EqualName(name, "Transfer-Encoding"))
        NotImplemented_nid_no_patch("HTTP manual framing headers");
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
    if (!FindAny(id)) return ERROR_INVALID_ID;
    if (enabled != 0) NotImplemented_nid_no_patch("HTTP asynchronous requests");
    return 0;
}
int APS5_VABI sceHttpSetAutoRedirect(int id, int enabled) {
    if (!FindAny(id)) return ERROR_INVALID_ID;
    if (enabled != 0) NotImplemented_nid_no_patch("HTTP automatic redirects");
    return 0;
}

int APS5_VABI sceHttpSendRequest(int id, const void* data, std::size_t size) {
    auto request = Find(id, Kind::Request);
    if (!request) return ERROR_INVALID_ID;
    std::lock_guard lock(request->mutex);
    if (request->aborted) return ERROR_ABORTED;
    if (request->transfer) return ERROR_INVALID_VALUE;
    if ((!data && size) || size != request->contentLength || size > INT64_MAX) return ERROR_INVALID_VALUE;
    if (request->url.starts_with("https:")) NotImplemented_nid_no_patch("HTTP TLS transport");
    if (HasCallbacks(id)) NotImplemented_nid_no_patch("HTTP request status callbacks during transport");
    if ((request->method == "GET" || request->method == "HEAD") && size) return ERROR_INVALID_VALUE;
    if (!InitializeCurl()) return ERROR_NETWORK;
    request->transfer = std::make_unique<Transfer>();
    auto& transfer = *request->transfer;
    if (!transfer.easy || !transfer.multi) return transfer.error = ERROR_OUT_OF_MEMORY;
    transfer.headerLimit = request->settings.headerLimit;
    const auto set = [&](CURLoption option, auto value) {
        if (curl_easy_setopt(transfer.easy, option, value) != CURLE_OK) throw std::runtime_error("HTTP curl option configuration failed");
    };
    set(CURLOPT_URL, request->url.c_str());
    set(CURLOPT_PROTOCOLS_STR, "http");
    set(CURLOPT_PROXY, "");
    set(CURLOPT_NOSIGNAL, 1L);
    set(CURLOPT_FORBID_REUSE, request->settings.keepAlive ? 0L : 1L);
    set(CURLOPT_HTTP_VERSION, request->settings.version);
    set(CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>((std::uint64_t{request->settings.connectTimeout} + 999) / 1000));
    set(CURLOPT_USERAGENT, request->settings.agent.c_str());
    set(CURLOPT_HEADERFUNCTION, Header);
    set(CURLOPT_HEADERDATA, &transfer);
    set(CURLOPT_WRITEFUNCTION, Body);
    set(CURLOPT_WRITEDATA, &transfer);
    set(CURLOPT_CUSTOMREQUEST, request->method.c_str());
    if (request->method == "HEAD") set(CURLOPT_NOBODY, 1L);
    else if (size || request->method == "POST" || request->method == "PUT") {
        set(CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(size));
        set(CURLOPT_COPYPOSTFIELDS, size ? data : "");
    }
    const auto append = [&](const std::string& line) {
        auto* next = curl_slist_append(transfer.outgoing, line.c_str());
        if (!next) throw std::bad_alloc();
        transfer.outgoing = next;
    };
    append("Expect:");
    if (!request->settings.keepAlive) append("Connection: close");
    for (const auto& [name, value] : request->settings.headers) append(name + (value.empty() ? ";" : ": " + value));
    set(CURLOPT_HTTPHEADER, transfer.outgoing);
    if (curl_multi_add_handle(transfer.multi, transfer.easy) != CURLM_OK) return transfer.error = ERROR_NETWORK;
    transfer.attached = true;
    const int error = Drive(*request, true);
    return error ? error : transfer.ready ? 0 : ERROR_NETWORK;
}

int APS5_VABI sceHttpReadData(int id, void* output, std::size_t size) {
    auto request = Find(id, Kind::Request);
    if (!request) return ERROR_INVALID_ID;
    if (!output && size) return ERROR_INVALID_VALUE;
    std::lock_guard lock(request->mutex);
    if (request->aborted) return ERROR_ABORTED;
    if (!request->transfer) return ERROR_NETWORK;
    auto& transfer = *request->transfer;
    if (transfer.error) return transfer.error;
    if (!size) return 0;
    if (transfer.consumed == transfer.body.size() && !transfer.done) {
        transfer.body.clear();
        transfer.consumed = 0;
        if (curl_easy_pause(transfer.easy, CURLPAUSE_CONT) != CURLE_OK) return transfer.error = ERROR_NETWORK;
        if (const int error = Drive(*request, false)) return error;
    }
    const auto count = std::min({size, transfer.body.size() - transfer.consumed, request->settings.readBlock, std::size_t{INT_MAX}});
    if (count) std::memcpy(output, transfer.body.data() + transfer.consumed, count);
    transfer.consumed += count;
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
    if (!request->transfer || !request->transfer->ready) return ERROR_NETWORK;
    *status = request->transfer->status;
    return 0;
}

int APS5_VABI sceHttpGetAllResponseHeaders(int id, char** headers, std::size_t* size) {
    if (!headers || !size) return ERROR_INVALID_VALUE;
    auto request = Find(id, Kind::Request);
    if (!request) return ERROR_INVALID_ID;
    std::lock_guard lock(request->mutex);
    if (!request->transfer || !request->transfer->ready) return ERROR_NETWORK;
    *headers = request->transfer->headers.data();
    *size = request->transfer->headers.size();
    return 0;
}

int APS5_VABI sceHttpGetResponseContentLength(int id, int* result, std::uint64_t* size) {
    if (!result || !size) return ERROR_INVALID_VALUE;
    auto request = Find(id, Kind::Request);
    if (!request) return ERROR_INVALID_ID;
    std::lock_guard lock(request->mutex);
    if (!request->transfer || !request->transfer->ready) return ERROR_NETWORK;
    curl_off_t length = -1;
    if (curl_easy_getinfo(request->transfer->easy, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &length) != CURLE_OK) return ERROR_NETWORK;
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
