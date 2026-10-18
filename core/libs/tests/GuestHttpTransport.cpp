#include "prx/libc/include/general/VabiMacros.hpp"
#include "SceTypes.hpp"
#include "prx/libSceSsl/SslTypes.hpp"
#include "SslCertificateFixture.hpp"
#include "HttpTlsFixture.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <source_location>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

extern "C" {
int APS5_VABI sceHttpInit_nid_postfix(int, int, std::uint64_t);
int APS5_VABI sceHttpTerm_nid_postfix(int);
int APS5_VABI sceHttpCreateTemplate(int, const char*, int, int);
int APS5_VABI sceHttpCreateConnectionWithURL(int, const char*, int);
int APS5_VABI sceHttpCreateRequest2(int, const char*, const char*, std::uint64_t);
int APS5_VABI sceHttpCreateRequest(int, int, const char*, std::uint64_t);
int APS5_VABI sceHttpCreateRequestWithURL2(int, const char*, const char*, std::uint64_t);
int APS5_VABI sceHttpDeleteRequest(int);
int APS5_VABI sceHttpDeleteConnection(int);
int APS5_VABI sceHttpDeleteTemplate(int);
int APS5_VABI sceHttpAddRequestHeader(int, const char*, const char*, std::uint32_t);
int APS5_VABI sceHttpSendRequest(int, const void*, std::size_t);
int APS5_VABI sceHttpReadData(int, void*, std::size_t);
int APS5_VABI sceHttpGetStatusCode(int, int*);
int APS5_VABI sceHttpGetAllResponseHeaders(int, char**, std::size_t*);
int APS5_VABI sceHttpGetResponseContentLength(int, int*, std::uint64_t*);
int APS5_VABI sceHttpSetRecvTimeOut(int, std::uint32_t);
int APS5_VABI sceHttpSetResponseHeaderMaxSize(int, std::uint64_t);
int APS5_VABI sceHttpSetRecvBlockSize(int, std::uint32_t);
int APS5_VABI sceHttpAbortRequest(int);
int APS5_VABI sceHttpSetNonblock(int, int);
int APS5_VABI sceHttpGetNonblock(int, int*);
int APS5_VABI sceHttpTryGetNonblock(int, int*);
int APS5_VABI sceHttpTrySetNonblock(int, int);
int APS5_VABI sceHttpCreateEpoll(int, HttpEpollHandle*);
int APS5_VABI sceHttpDestroyEpoll(int, HttpEpollHandle);
int APS5_VABI sceHttpSetEpoll(int, HttpEpollHandle, void*);
int APS5_VABI sceHttpUnsetEpoll(int);
int APS5_VABI sceHttpGetEpoll(int, HttpEpollHandle*, void**);
int APS5_VABI sceHttpWaitRequest(HttpEpollHandle, HttpNBEvent*, int, int);
int APS5_VABI sceHttpSetAutoRedirect(int, int);
int APS5_VABI sceHttpSetInflateGZIPEnabled(int, int);
int APS5_VABI sceHttpSetCookieEnabled(int, int);
int APS5_VABI sceHttpSetChunkedTransferEnabled(int, int);
int APS5_VABI sceHttpsLoadCert(int, int, SceSsl::Data**, SceSsl::Data*, SceSsl::Data*);
int APS5_VABI sceHttpsUnloadCert(int);
int APS5_VABI sceHttpsGetSslError(int, int*, std::uint32_t*);
int APS5_VABI sceHttpsDisableOption(int, std::uint32_t);
int APS5_VABI sceHttpsEnableOption(int, std::uint32_t);
int APS5_VABI sceHttpsSetSslVersion(int, int);
}

static void Require(bool condition, const std::source_location location = std::source_location::current()) {
    if (!condition) {
        std::fprintf(stderr, "HTTP transport check failed at %s:%u\n", location.file_name(), location.line());
        std::_Exit(1);
    }
}

constexpr int InvalidId = static_cast<int>(0x80431100);
constexpr int InvalidValue = static_cast<int>(0x804311fe);
constexpr int Network = static_cast<int>(0x80431063);
constexpr int Aborted = static_cast<int>(0x80431080);
constexpr int Again = static_cast<int>(0x80431082);

template<typename TFunction>
static bool Unsupported(TFunction function) {
    try { function(); }
    catch (const std::runtime_error&) { return true; }
    return false;
}

static std::string Read(int request, std::size_t block = 137) {
    std::vector<char> buffer(block + 16, 'Z');
    std::string body;
    for (;;) {
        std::fill(buffer.begin(), buffer.end(), 'Z');
        const int count = sceHttpReadData(request, buffer.data(), block);
        Require(count >= 0 && static_cast<std::size_t>(count) <= block);
        Require(std::all_of(buffer.begin() + count, buffer.end(), [](char c) { return c == 'Z'; }));
        if (!count) break;
        body.append(buffer.data(), count);
    }
    Require(sceHttpReadData(request, buffer.data(), block) == 0);
    return body;
}

static int Request(int connection, const char* path, const char* method = "GET", std::size_t length = 0) {
    const int request = sceHttpCreateRequest2(connection, method, path, length);
    Require(request > 0);
    return request;
}

static void WaitStarted(int connection, const char* path) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    do {
        const auto query = std::string("/started?path=") + path;
        const int probe = Request(connection, query.c_str());
        Require(sceHttpSendRequest(probe, nullptr, 0) == 0);
        const auto body = Read(probe);
        Require(sceHttpDeleteRequest(probe) == 0);
        if (body == "yes") return;
        std::this_thread::yield();
    } while (std::chrono::steady_clock::now() < deadline);
    Require(false);
}

static void Basic(int connection) {
    Require(sceHttpAddRequestHeader(connection, "X-Inherited", "original", 0) == 0);
    int request = Request(connection, "/binary");
    Require(sceHttpAddRequestHeader(connection, "X-Inherited", "new", 0) == 0);
    Require(sceHttpAddRequestHeader(request, "X-Test", "first", 0) == 0);
    Require(sceHttpAddRequestHeader(request, "x-test", "last", 0) == 0);
    Require(sceHttpAddRequestHeader(request, "X-Test", "extra", 1) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    int status = 0;
    Require(sceHttpGetStatusCode(request, &status) == 0 && status == 200);
    int kind = -1;
    std::uint64_t size = 0;
    Require(sceHttpGetResponseContentLength(request, &kind, &size) == 0 && kind == 0 && size == 1024);
    char* headers = nullptr;
    std::size_t headerSize = 0;
    Require(sceHttpGetAllResponseHeaders(request, &headers, &headerSize) == 0);
    Require(headers && headerSize == std::strlen(headers));
    Require(std::string(headers, headerSize).find("X-Echo: last,extra") != std::string::npos);
    Require(std::string(headers, headerSize).find("X-Inherited: original") != std::string::npos);
    Require(std::string(headers, headerSize).find("X-Template: base") != std::string::npos);
    const auto body = Read(request, 7);
    Require(body.size() == 1024);
    for (std::size_t i = 0; i < body.size(); ++i) Require(static_cast<unsigned char>(body[i]) == i % 256);
    Require(sceHttpSendRequest(request, nullptr, 0) == InvalidValue);
    Require(sceHttpDeleteRequest(request) == 0);
    Require(sceHttpReadData(request, nullptr, 0) == InvalidId);
    Require(sceHttpDeleteRequest(request) == InvalidId);

    for (const char* method : {"POST", "PUT", "PATCH"}) {
        std::string upload(100000, '\0');
        for (std::size_t i = 0; i < upload.size(); ++i) upload[i] = static_cast<char>(i % 251);
        request = Request(connection, "/echo", method, upload.size());
        Require(sceHttpSendRequest(request, upload.data(), upload.size() - 1) == InvalidValue);
        Require(sceHttpSendRequest(request, upload.data(), upload.size()) == 0);
        Require(Read(request, 1009) == upload);
        Require(sceHttpDeleteRequest(request) == 0);
    }
    request = sceHttpCreateRequest(connection, 2, "/binary", 0);
    Require(request > 0 && sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(Read(request).empty());
    Require(sceHttpDeleteRequest(request) == 0);
    request = Request(connection, "/missing");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(sceHttpGetStatusCode(request, &status) == 0 && status == 404);
    Require(Read(request) == "missing");
    Require(sceHttpDeleteRequest(request) == 0);
}

static void Contexts(int firstContext, int firstConnection, const char* url) {
    const int secondContext = sceHttpInit_nid_postfix(0, 0, 65536);
    const int secondTemplate = sceHttpCreateTemplate(secondContext, "context-test", 2, 0);
    const int secondConnection = sceHttpCreateConnectionWithURL(secondTemplate, url, 0);
    Require(secondContext > 0 && secondTemplate > 0 && secondConnection > 0);
    const int first = Request(firstConnection, "/slow/isolation");
    std::atomic<int> result{0};
    std::thread sender([&] { result = sceHttpSendRequest(first, nullptr, 0); });
    WaitStarted(firstConnection, "/slow/isolation");
    const int second = Request(secondConnection, "/binary");
    Require(sceHttpSendRequest(second, nullptr, 0) == 0);
    Require(sceHttpTerm_nid_postfix(firstContext) == 0);
    sender.join();
    Require(result == Aborted);
    Require(Read(second).size() == 1024);
    Require(sceHttpDeleteRequest(second) == 0);
    Require(sceHttpDeleteConnection(secondConnection) == 0);
    Require(sceHttpDeleteTemplate(secondTemplate) == 0);
    Require(sceHttpTerm_nid_postfix(secondContext) == 0);
}

static void Streaming(int connection) {
    for (const char* path : {"/chunked", "/close", "/interim"}) {
        const int request = Request(connection, path);
        Require(sceHttpSetRecvBlockSize(request, 11) == 0);
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        Require(Read(request, 31) == std::string("hello\0world", 11));
        int lengthResult = 0;
        std::uint64_t length = 123;
        Require(sceHttpGetResponseContentLength(request, &lengthResult, &length) == 0);
        if (std::strcmp(path, "/interim") == 0) Require(lengthResult == 0 && length == 11);
        else Require(lengthResult == static_cast<int>(0x80431071) && length == 0);
        int status = 0;
        Require(sceHttpGetStatusCode(request, &status) == 0 && status == 200);
        Require(sceHttpDeleteRequest(request) == 0);
    }
    const int request = Request(connection, "/large");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    std::vector<unsigned char> buffer(1024);
    std::size_t total = 0;
    for (;;) {
        const int count = sceHttpReadData(request, buffer.data(), buffer.size());
        Require(count >= 0 && count <= 1024);
        if (!count) break;
        for (int i = 0; i < count; ++i) Require(buffer[i] == (total + i) % 256);
        total += count;
    }
    Require(total == 8 * 1024 * 1024);
    Require(sceHttpDeleteRequest(request) == 0);
}

static void Failures(int connection) {
    Require(sceHttpCreateRequest2(-1, "GET", "/", 0) == InvalidId);
    Require(sceHttpAddRequestHeader(connection, "bad\r\nname", "x", 0) == InvalidValue);
    Require(sceHttpAddRequestHeader(connection, "X-Test", "x\r\nInjected: yes", 0) == InvalidValue);
    Require(sceHttpCreateRequest2(connection, "GET\r\n", "/", 0) == InvalidValue);
    Require(sceHttpCreateRequestWithURL2(connection, "GET", "file:///tmp/data", 0) == static_cast<int>(0x80433060));
    int secure = sceHttpCreateRequestWithURL2(connection, "GET", "https://127.0.0.1/", 0);
    Require(secure > 0);
    Require(sceHttpSendRequest(secure, nullptr, 0) == Network);
    Require(sceHttpDeleteRequest(secure) == 0);
    int request = Request(connection, "/headers");
    Require(sceHttpSetNonblock(request, 0) == 0);
    Require(sceHttpSetAutoRedirect(request, 1) == 0);
    Require(sceHttpSetInflateGZIPEnabled(request, 1) == 0);
    Require(sceHttpSetResponseHeaderMaxSize(request, 64) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) < 0);
    Require(sceHttpDeleteRequest(request) == 0);
    request = Request(connection, "/slow");
    Require(sceHttpSetRecvTimeOut(request, 50000) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == Network);
    Require(sceHttpDeleteRequest(request) == 0);
    for (const char* path : {"/truncated", "/badchunk", "/badgzip"}) {
        request = Request(connection, path);
        int result = sceHttpSendRequest(request, nullptr, 0);
        char buffer[17];
        while (result == 0 || result > 0) {
            result = sceHttpReadData(request, buffer, sizeof(buffer));
            if (result == 0) break;
        }
        Require(result == Network);
        Require(sceHttpDeleteRequest(request) == 0);
    }
}

static void Session(int context, int connection, const char* url) {
    int chunked = Request(connection, "/echo", "POST");
    Require(sceHttpSetChunkedTransferEnabled(chunked, 1) == 0);
    std::string upload(100000, 'A');
    for (std::size_t index = 0; index < upload.size(); ++index) upload[index] = static_cast<char>(index % 251);
    Require(sceHttpSendRequest(chunked, upload.data(), upload.size()) == 0);
    Require(Read(chunked, 137) == upload);
    Require(sceHttpDeleteRequest(chunked) == 0);
    for (int code : {301, 302, 303, 307, 308}) {
        const auto path = "/redirect/" + std::to_string(code);
        const int request = Request(connection, path.c_str(), "POST", 7);
        if (code != 302) Require(sceHttpSetAutoRedirect(request, 1) == 0);
        Require(sceHttpSendRequest(request, "payload", 7) == 0);
        Require(Read(request) == (code == 307 || code == 308 ? "POST:payload" : "GET:"));
        int status = 0;
        Require(sceHttpGetStatusCode(request, &status) == 0 && status == 200);
        Require(sceHttpDeleteRequest(request) == 0);
    }
    int request = Request(connection, "/redirect/302");
    Require(sceHttpSetAutoRedirect(request, 0) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(Read(request) == "discard");
    Require(sceHttpDeleteRequest(request) == 0);
    request = Request(connection, "/loop");
    Require(sceHttpSetAutoRedirect(request, 1) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == Network);
    Require(sceHttpDeleteRequest(request) == 0);
    for (const char* path : {"/gzip", "/deflate"}) {
        request = Request(connection, path);
        Require(sceHttpSetInflateGZIPEnabled(request, 1) == 0);
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        Require(Read(request, 3) == std::string("hello\0world", 11));
        Require(sceHttpDeleteRequest(request) == 0);
        request = Request(connection, path);
        Require(sceHttpSetInflateGZIPEnabled(request, 0) == 0);
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        const auto encoded = Read(request, 3);
        Require(encoded.size() > 11 && static_cast<unsigned char>(encoded[0]) == (std::strcmp(path, "/gzip") == 0 ? 0x1f : 0x78));
        Require(sceHttpDeleteRequest(request) == 0);
    }
    Require(sceHttpSetCookieEnabled(connection, 1) == 0);
    request = Request(connection, "/cookies/set");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Read(request);
    Require(sceHttpDeleteRequest(request) == 0);
    request = Request(connection, "/cookies/check");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(Read(request) == "session=alpha");
    Require(sceHttpDeleteRequest(request) == 0);
    std::vector<std::thread> readers;
    for (int index = 0; index < 4; ++index) readers.emplace_back([&] {
        const int current = Request(connection, "/cookies/check");
        Require(sceHttpSendRequest(current, nullptr, 0) == 0);
        Require(Read(current) == "session=alpha");
        Require(sceHttpDeleteRequest(current) == 0);
    });
    for (auto& reader : readers) reader.join();
    request = Request(connection, "/outside-cookie");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(Read(request).empty());
    Require(sceHttpDeleteRequest(request) == 0);
    request = Request(connection, "/cookies/check");
    Require(sceHttpSetCookieEnabled(request, 0) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(Read(request).empty());
    Require(sceHttpDeleteRequest(request) == 0);
    const int isolated = sceHttpInit_nid_postfix(0, 0, 65536);
    const int object = sceHttpCreateTemplate(isolated, "isolated", 2, 0);
    const int other = sceHttpCreateConnectionWithURL(object, url, 0);
    Require(sceHttpSetCookieEnabled(other, 1) == 0);
    request = Request(other, "/cookies/check");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(Read(request).empty());
    Require(sceHttpTerm_nid_postfix(isolated) == 0);
    Require(sceHttpSetCookieEnabled(context, 2) == InvalidValue);
}

static SceSsl::Data Certificate(const char* text) {
    return {reinterpret_cast<std::uint8_t*>(const_cast<char*>(text)), std::strlen(text)};
}

static void Tls(int context, int connection, const char* url, bool mutual) {
    Require(sceHttpsLoadCert(context, -1, nullptr, nullptr, nullptr) == InvalidValue);
    Require(sceHttpsLoadCert(context, 1, nullptr, nullptr, nullptr) == InvalidValue);
    SceSsl::Data empty{};
    auto* invalid = &empty;
    Require(sceHttpsLoadCert(context, 1, &invalid, nullptr, nullptr) == InvalidValue);
    int request = Request(connection, "/binary");
    Require(sceHttpSendRequest(request, nullptr, 0) == Network);
    int error = 0;
    std::uint32_t detail = 0;
    Require(Unsupported([&] { sceHttpsGetSslError(request, &error, &detail); }));
    Require(sceHttpDeleteRequest(request) == 0);
    if (!mutual) {
        request = Request(connection, "/binary");
        Require(sceHttpsEnableOption(request, 0xa5) == 0);
        Require(sceHttpsDisableOption(request, 0x20) == 0);
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        Require(Read(request).size() == 1024);
        Require(sceHttpDeleteRequest(request) == 0);
    }
    auto authority = Certificate(RootPem);
    if (!mutual) authority = {const_cast<std::uint8_t*>(RootDer.data()), RootDer.size()};
    auto* pointer = &authority;
    Require(sceHttpsLoadCert(context, 1, &pointer, nullptr, nullptr) == 0);
    if (mutual) {
        request = Request(connection, "/binary");
        Require(sceHttpSendRequest(request, nullptr, 0) == Network);
        Require(sceHttpDeleteRequest(request) == 0);
        auto cert = Certificate(ClientPem);
        auto key = Certificate(ClientKey);
        auto wrong = Certificate(RootKey);
        Require(sceHttpsLoadCert(context, 1, &pointer, &cert, &wrong) == InvalidValue);
        Require(sceHttpsLoadCert(context, 1, &pointer, &cert, &key) == 0);
    }
    request = Request(connection, "/binary");
    Require(sceHttpsSetSslVersion(request, 5) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(Read(request).size() == 1024);
    Require(sceHttpsGetSslError(request, &error, &detail) == 0 && error == 0 && detail == 0);
    Require(sceHttpDeleteRequest(request) == 0);
    if (mutual) {
        SceSsl::Data cert{const_cast<std::uint8_t*>(ClientDer.data()), ClientDer.size()};
        SceSsl::Data key{const_cast<std::uint8_t*>(ClientKeyDer.data()), ClientKeyDer.size()};
        Require(sceHttpsLoadCert(context, 1, &pointer, &cert, &key) == 0);
        request = Request(connection, "/binary");
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        Require(Read(request).size() == 1024);
        Require(sceHttpDeleteRequest(request) == 0);
    }
    request = Request(connection, "/downgrade");
    Require(sceHttpSendRequest(request, nullptr, 0) == Network);
    Require(sceHttpDeleteRequest(request) == 0);
    auto wrongHost = std::string(url);
    wrongHost.replace(wrongHost.find("localhost"), 9, "127.0.0.1");
    request = sceHttpCreateRequestWithURL2(connection, "GET", wrongHost.c_str(), 0);
    Require(request > 0 && sceHttpSendRequest(request, nullptr, 0) == Network);
    Require(Unsupported([&] { sceHttpsGetSslError(request, &error, &detail); }));
    Require(sceHttpDeleteRequest(request) == 0);
    request = sceHttpCreateRequestWithURL2(connection, "GET", wrongHost.c_str(), 0);
    Require(sceHttpsDisableOption(request, 4) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Read(request);
    Require(sceHttpDeleteRequest(request) == 0);
    Require(sceHttpsUnloadCert(context) == 0);
    request = Request(connection, "/binary");
    Require(sceHttpSendRequest(request, nullptr, 0) == Network);
    Require(sceHttpDeleteRequest(request) == 0);
}

static void Expired(int context, int connection) {
    auto authority = Certificate(RootPem);
    auto* pointer = &authority;
    Require(sceHttpsLoadCert(context, 1, &pointer, nullptr, nullptr) == 0);
    int request = Request(connection, "/binary");
    Require(sceHttpSendRequest(request, nullptr, 0) == Network);
    int error = 0;
    std::uint32_t detail = 0;
    Require(Unsupported([&] { sceHttpsGetSslError(request, &error, &detail); }));
    Require(sceHttpDeleteRequest(request) == 0);
    request = Request(connection, "/binary");
    Require(sceHttpsDisableOption(request, 8) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(Read(request).size() == 1024);
    Require(sceHttpDeleteRequest(request) == 0);
}

static std::string ReadAsync(int request, HttpEpollHandle epoll) {
    std::string body;
    char data[4096];
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    for (;;) {
        Require(std::chrono::steady_clock::now() < deadline);
        const int count = sceHttpReadData(request, data, sizeof(data));
        if (!count) return body;
        if (count == Again) {
            HttpNBEvent event;
            Require(sceHttpWaitRequest(epoll, &event, 1, 100000) >= 0);
        } else {
            Require(count > 0 && count <= static_cast<int>(sizeof(data)));
            body.append(data, count);
        }
    }
}

static void AsyncTls(int context, int connection) {
    HttpEpollHandle epoll = nullptr;
    Require(sceHttpCreateEpoll(context, &epoll) == 0);
    Require(sceHttpSetEpoll(connection, epoll, nullptr) == 0);
    Require(sceHttpSetNonblock(connection, 1) == 0);
    int request = Request(connection, "/binary");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    HttpNBEvent event;
    Require(sceHttpWaitRequest(epoll, &event, 1, 2000000) == 1 && (event.events & 8));
    char byte;
    Require(sceHttpReadData(request, &byte, 1) == Network);
    Require(sceHttpDeleteRequest(request) == 0);
    auto authority = Certificate(RootPem);
    auto* pointer = &authority;
    Require(sceHttpsLoadCert(context, 1, &pointer, nullptr, nullptr) == 0);
    request = Request(connection, "/binary");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(ReadAsync(request, epoll).size() == 1024);
    Require(sceHttpDeleteRequest(request) == 0);
    Require(sceHttpDestroyEpoll(context, epoll) == 0);
}

static void Async(int context, int connection, const char* url) {
    static_assert(sizeof(HttpNBEvent) == 24);
    static_assert(offsetof(HttpNBEvent, userArg) == 16);
    HttpEpollHandle epoll = nullptr;
    Require(sceHttpCreateEpoll(context, &epoll) == 0);
    Require(sceHttpSetEpoll(-1, epoll, nullptr) == InvalidId);
    Require(sceHttpSetNonblock(connection, 2) == InvalidValue);
    Require(sceHttpGetNonblock(connection, nullptr) == InvalidValue);
    Require(sceHttpTrySetNonblock(connection, 1) == 0);
    int enabled = -1;
    Require(sceHttpTryGetNonblock(connection, &enabled) == 0 && enabled == 1);
    int argument = 42;
    Require(sceHttpSetEpoll(connection, epoll, &argument) == 0);
    int request = Request(connection, "/slow/async");
    HttpEpollHandle inherited = nullptr;
    void* pointer = nullptr;
    Require(sceHttpGetEpoll(request, &inherited, &pointer) == 0 && inherited == epoll && pointer == &argument);
    Require(sceHttpGetEpoll(request, &inherited, nullptr) == 0 && inherited == epoll);
    Require(sceHttpGetEpoll(request, nullptr, &pointer) == InvalidValue);
    Require(sceHttpGetNonblock(request, &enabled) == 0 && enabled == 1);
    const auto start = std::chrono::steady_clock::now();
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(std::chrono::steady_clock::now() - start < std::chrono::milliseconds(250));
    int status = 123;
    Require(sceHttpGetStatusCode(request, &status) == Again && status == 123);
    char* headers = reinterpret_cast<char*>(&argument);
    std::size_t length = 42;
    Require(sceHttpGetAllResponseHeaders(request, &headers, &length) == Again && length == 42);
    char data[16];
    Require(sceHttpReadData(request, data, sizeof(data)) == Again);
    HttpNBEvent events[2]{};
    events[1].id = -999;
    Require(sceHttpWaitRequest(epoll, events, 1, 2000000) == 1);
    Require(events[0].id == request && events[0].userArg == &argument && (events[0].events & 2));
    Require(events[1].id == -999);
    Require(ReadAsync(request, epoll) == std::string("hello\0world", 11));
    Require(sceHttpGetStatusCode(request, &status) == 0 && status == 200);
    Require(sceHttpDeleteRequest(request) == 0);
    Require(sceHttpWaitRequest(epoll, events, 2, 0) == 0);

    for (const char* path : {"/chunked", "/close", "/gzip", "/slowbody", "/large"}) {
        request = Request(connection, path);
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        const auto body = ReadAsync(request, epoll);
        if (std::strcmp(path, "/large") == 0) {
            Require(body.size() == 8 * 1024 * 1024);
            for (std::size_t i = 0; i < body.size(); ++i) Require(static_cast<unsigned char>(body[i]) == i % 256);
        } else Require(body == std::string("hello\0world", 11));
        Require(sceHttpDeleteRequest(request) == 0);
    }
    request = Request(connection, "/echo", "POST", 100000);
    std::string upload(100000, 'u');
    Require(sceHttpSendRequest(request, upload.data(), upload.size()) == 0);
    upload.assign(100000, 'x');
    Require(ReadAsync(request, epoll) == std::string(100000, 'u'));
    Require(sceHttpDeleteRequest(request) == 0);

    std::vector<int> requests;
    for (int i = 0; i < 8; ++i) {
        const int current = Request(connection, "/binary");
        requests.push_back(current);
        Require(sceHttpSendRequest(current, nullptr, 0) == 0);
    }
    for (int current : requests) {
        Require(ReadAsync(current, epoll).size() == 1024);
        Require(sceHttpDeleteRequest(current) == 0);
    }
    request = Request(connection, "/slow/abort-async");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(sceHttpAbortRequest(request) == 0);
    Require(sceHttpWaitRequest(epoll, events, 1, 2000000) == 1);
    Require(events[0].id == request && (events[0].events & 0x10));
    Require(sceHttpReadData(request, data, sizeof(data)) == Aborted);
    Require(sceHttpDeleteRequest(request) == 0);

    request = Request(connection, "/slow/timeout-async");
    Require(sceHttpSetRecvTimeOut(request, 20000) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(sceHttpWaitRequest(epoll, events, 1, 2000000) == 1);
    Require(events[0].id == request && (events[0].events & 8));
    Require(sceHttpReadData(request, data, sizeof(data)) == Network);
    status = 123;
    Require(sceHttpGetStatusCode(request, &status) == Network && status == 123);
    Require(sceHttpDeleteRequest(request) == 0);

    request = Request(connection, "/slow/detached-async");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(sceHttpUnsetEpoll(request) == 0);
    Require(sceHttpWaitRequest(epoll, events, 1, 500000) == 0);
    Require(sceHttpSetEpoll(request, epoll, &argument) == 0);
    Require(sceHttpWaitRequest(epoll, events, 1, 0) == 1 && events[0].id == request);
    Require(ReadAsync(request, epoll) == std::string("hello\0world", 11));
    Require(sceHttpDeleteRequest(request) == 0);

    request = Request(connection, "/slow/deleted-async");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(sceHttpDeleteRequest(request) == 0);
    Require(sceHttpWaitRequest(epoll, events, 2, 0) == 0);
    request = Request(connection, "/slow/destroyed-async");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(sceHttpDestroyEpoll(context, epoll) == 0);
    Require(sceHttpDeleteRequest(request) == 0);
    Require(sceHttpSetNonblock(connection, 0) == 0);
    Require(sceHttpUnsetEpoll(connection) == 0);

    const int other = sceHttpInit_nid_postfix(0, 0, 65536);
    HttpEpollHandle own = nullptr;
    Require(sceHttpCreateEpoll(other, &own) == 0);
    Require(sceHttpSetEpoll(connection, own, nullptr) == InvalidId);
    Require(sceHttpDestroyEpoll(context, own) == InvalidId);
    std::atomic<int> result{-999};
    std::thread waiter([&] { HttpNBEvent event; result = sceHttpWaitRequest(own, &event, 1, -1); });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    Require(sceHttpTerm_nid_postfix(other) == 0);
    waiter.join();
    Require(result == 0 || result == InvalidId);
    Require(sceHttpDeleteConnection(-1) == InvalidId);
    for (int i = 0; i < 16; ++i) {
        const int temporary = sceHttpInit_nid_postfix(0, 0, 65536);
        const int object = sceHttpCreateTemplate(temporary, "async teardown", 2, 0);
        const int parent = sceHttpCreateConnectionWithURL(object, url, 0);
        Require(sceHttpSetNonblock(parent, 1) == 0);
        const int current = Request(parent, "/slow/terminated-async");
        Require(sceHttpSendRequest(current, nullptr, 0) == 0);
        Require(sceHttpTerm_nid_postfix(temporary) == 0);
        Require(sceHttpReadData(current, data, sizeof(data)) == InvalidId);
    }
}

static void Lifecycle(int context, int connection) {
    int request = Request(connection, "/slow/abort");
    Require(sceHttpDeleteConnection(connection) == static_cast<int>(0x80431021));
    std::atomic<bool> entered{false};
    std::atomic<int> result{0};
    std::thread sender([&] { entered = true; result = sceHttpSendRequest(request, nullptr, 0); });
    while (!entered) std::this_thread::yield();
    WaitStarted(connection, "/slow/abort");
    Require(sceHttpAbortRequest(request) == 0);
    sender.join();
    Require(result == Aborted);
    Require(sceHttpDeleteRequest(request) == 0);
    request = Request(connection, "/slow/delete");
    entered = false;
    std::thread deleted([&] { entered = true; result = sceHttpSendRequest(request, nullptr, 0); });
    while (!entered) std::this_thread::yield();
    WaitStarted(connection, "/slow/delete");
    Require(sceHttpDeleteRequest(request) == 0);
    deleted.join();
    Require(result == Aborted);
    Require(sceHttpDeleteRequest(request) == InvalidId);
    request = Request(connection, "/slowbody");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    std::thread reader([&] {
        char buffer[8];
        result = sceHttpReadData(request, buffer, sizeof(buffer));
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    Require(sceHttpAbortRequest(request) == 0);
    reader.join();
    Require(result == Aborted);
    Require(sceHttpDeleteRequest(request) == 0);
    std::vector<std::thread> threads;
    std::atomic<int> passed{0};
    for (int i = 0; i < 8; ++i) threads.emplace_back([&] {
        const int current = Request(connection, "/binary");
        Require(sceHttpSendRequest(current, nullptr, 0) == 0);
        Require(Read(current).size() == 1024);
        Require(sceHttpDeleteRequest(current) == 0);
        ++passed;
    });
    for (auto& thread : threads) thread.join();
    Require(passed == 8);
    request = Request(connection, "/slow/terminate");
    entered = false;
    std::thread terminated([&] { entered = true; result = sceHttpSendRequest(request, nullptr, 0); });
    while (!entered) std::this_thread::yield();
    WaitStarted(connection, "/slow/terminate");
    Require(sceHttpTerm_nid_postfix(context) == 0);
    terminated.join();
    Require(result == Aborted);
    Require(sceHttpDeleteRequest(request) == InvalidId);
}

int main(int argc, char** argv) {
    Require(argc == 3);
    const int context = sceHttpInit_nid_postfix(0, 0, 65536);
    const int object = sceHttpCreateTemplate(context, "AnyPS5-test", 2, 0);
    Require(sceHttpAddRequestHeader(object, "X-Template", "base", 0) == 0);
    const int connection = sceHttpCreateConnectionWithURL(object, argv[1], 1);
    Require(context > 0 && object > 0 && connection > 0);
    const std::string mode(argv[2]);
    if (mode == "basic") Basic(connection);
    else if (mode == "streaming") Streaming(connection);
    else if (mode == "failures") Failures(connection);
    else if (mode == "session") Session(context, connection, argv[1]);
    else if (mode == "async") Async(context, connection, argv[1]);
    else if (mode == "async_tls") AsyncTls(context, connection);
    else if (mode == "tls" || mode == "mutual") Tls(context, connection, argv[1], mode == "mutual");
    else if (mode == "expired") Expired(context, connection);
    else if (mode == "lifecycle") { Lifecycle(context, connection); return 0; }
    else if (mode == "contexts") { Contexts(context, connection, argv[1]); return 0; }
    else Require(false);
    Require(sceHttpDeleteConnection(connection) == 0);
    Require(sceHttpDeleteTemplate(object) == 0);
    Require(sceHttpTerm_nid_postfix(context) == 0);
}
