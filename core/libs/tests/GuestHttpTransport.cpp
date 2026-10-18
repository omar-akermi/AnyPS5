#include "prx/libc/include/general/VabiMacros.hpp"
#include "SceTypes.hpp"
#include "prx/libSceSsl/SslTypes.hpp"
#include "SslCertificateFixture.hpp"
#include "HttpTlsFixture.hpp"
#include "prx/libSceHttp/src/Authentication.hpp"
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
int APS5_VABI sceHttpCreateRequestWithURL(int, int, const char*, std::uint64_t);
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
int APS5_VABI sceHttpSetResolveTimeOut(int, std::uint32_t);
int APS5_VABI sceHttpSetSendTimeOut(int, std::uint32_t);
int APS5_VABI sceHttpSetResolveRetry(int, std::int32_t);
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
int APS5_VABI sceHttpSetCookieRecvCallback(int, HttpCookieRecvCallback, void*);
int APS5_VABI sceHttpSetRedirectCallback(int, HttpRedirectCallback, void*);
int APS5_VABI sceHttpSetAuthEnabled(int, int);
int APS5_VABI sceHttpSetAuthInfoCallback(int, HttpAuthInfoCallback, void*);
int APS5_VABI sceHttpAuthCacheFlush(int);
int APS5_VABI sceHttpSetChunkedTransferEnabled(int, int);
int APS5_VABI sceHttpSetRequestStatusCallback(int, void (APS5_VABI *)(int, int, void*), void*);
int APS5_VABI sceHttpsLoadCert(int, int, SceSsl::Data**, SceSsl::Data*, SceSsl::Data*);
int APS5_VABI sceHttpsUnloadCert(int);
int APS5_VABI sceHttpsGetSslError(int, int*, std::uint32_t*);
int APS5_VABI sceHttpsDisableOption(int, std::uint32_t);
int APS5_VABI sceHttpsEnableOption(int, std::uint32_t);
int APS5_VABI sceHttpsSetSslVersion(int, int);
int APS5_VABI sceHttpsSetMinSslVersion(int, std::uint32_t);
int APS5_VABI sceHttpsSetSslCallback(int, HttpsCallback, void*);
int APS5_VABI sceHttpsGetCaList(int, SceSsl::CaList*);
int APS5_VABI sceHttpsFreeCaList(int, SceSsl::CaList*);
int APS5_VABI sceSslInit_nid_postfix(std::uint64_t);
int APS5_VABI sceSslTerm_nid_postfix(int);
int APS5_VABI sceSslGetMemoryPoolStats(int, SceSsl::MemoryPoolStats*);
void* APS5_VABI sceSslGetSubjectName(int, void*);
int APS5_VABI sceSslGetNameEntryCount(int, void*);
int APS5_VABI sceSslFreeSslCertName(int, void*);
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
    Require(sceHttpsGetSslError(request, &error, &detail) == 0 && error == static_cast<int>(0x80435060) && (detail & 32));
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
        request = Request(connection, "/binary");
        Require(sceHttpSendRequest(request, nullptr, 0) == Network);
        Require(sceHttpDeleteRequest(request) == 0);
        Require(sceHttpsEnableOption(connection, 2) == 0);
    }
    request = Request(connection, "/binary");
    Require(sceHttpsSetSslVersion(request, 5) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(Read(request).size() == 1024);
    Require(sceHttpsGetSslError(request, &error, &detail) == 0 && error == 0 && detail == 0);
    Require(sceHttpDeleteRequest(request) == 0);
    if (mutual) {
        Require(sceHttpsLoadCert(context, 1, &pointer, nullptr, nullptr) == 0);
        request = Request(connection, "/binary");
        Require(sceHttpSendRequest(request, nullptr, 0) == 0 && Read(request).size() == 1024);
        Require(sceHttpDeleteRequest(request) == 0);
        SceSsl::Data cert{const_cast<std::uint8_t*>(HttpTlsFixture::ClientDer.data()), HttpTlsFixture::ClientDer.size()};
        SceSsl::Data key{const_cast<std::uint8_t*>(HttpTlsFixture::ClientKeyDer.data()), HttpTlsFixture::ClientKeyDer.size()};
        Require(sceHttpsLoadCert(context, 1, &pointer, &cert, &key) == 0);
        request = Request(connection, "/binary");
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        Require(Read(request).size() == 1024);
        Require(sceHttpDeleteRequest(request) == 0);
        Require(sceHttpsDisableOption(connection, 2) == 0);
        request = Request(connection, "/binary");
        Require(sceHttpSendRequest(request, nullptr, 0) == Network);
        Require(sceHttpDeleteRequest(request) == 0);
        Require(sceHttpsEnableOption(connection, 2) == 0);
    }
    request = Request(connection, "/downgrade");
    Require(sceHttpSendRequest(request, nullptr, 0) == Network);
    Require(sceHttpDeleteRequest(request) == 0);
    auto wrongHost = std::string(url);
    wrongHost.replace(wrongHost.find("localhost"), 9, "127.0.0.1");
    request = sceHttpCreateRequestWithURL2(connection, "GET", wrongHost.c_str(), 0);
    Require(request > 0 && sceHttpSendRequest(request, nullptr, 0) == Network);
    Require(sceHttpsGetSslError(request, &error, &detail) == 0 && error == static_cast<int>(0x80435060) && (detail & 4));
    Require(sceHttpDeleteRequest(request) == 0);
    request = sceHttpCreateRequestWithURL2(connection, "GET", wrongHost.c_str(), 0);
    Require(sceHttpsDisableOption(request, 1) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Read(request);
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
    Require(sceHttpsGetSslError(request, &error, &detail) == 0 && error == static_cast<int>(0x80435060) && (detail & 8));
    Require(sceHttpDeleteRequest(request) == 0);
    request = Request(connection, "/binary");
    Require(sceHttpsDisableOption(request, 8) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(Read(request).size() == 1024);
    Require(sceHttpDeleteRequest(request) == 0);
}

static void MinimumVersion(int context, int connection) {
    auto authority = Certificate(RootPem);
    auto* pointer = &authority;
    Require(sceHttpsLoadCert(context, 1, &pointer, nullptr, nullptr) == 0);
    Require(sceHttpsSetMinSslVersion(connection, 6) == InvalidValue);
    Require(sceHttpsSetMinSslVersion(connection, UINT32_MAX) == InvalidValue);
    Require(sceHttpsSetSslVersion(connection, -1) == InvalidValue);
    Require(sceHttpsSetSslVersion(connection, 6) == InvalidValue);
    Require(sceHttpsSetSslVersion(connection, INT32_MAX) == InvalidValue);
    Require(sceHttpsSetSslVersion(-1, 5) == InvalidId);
    for (std::uint32_t version = 0; version <= 5; ++version) {
        const int request = Request(connection, "/binary");
        Require(sceHttpsSetMinSslVersion(request, version) == 0);
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        Require(Read(request).size() == 1024);
        Require(sceHttpDeleteRequest(request) == 0);
    }
    for (int version = 0; version <= 5; ++version) {
        Require(sceHttpsSetSslVersion(connection, version) == 0);
        const int request = Request(connection, "/binary");
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        Require(sceHttpsSetSslVersion(request, 0) == InvalidValue);
        Require(Read(request).size() == 1024);
        Require(sceHttpDeleteRequest(request) == 0);
    }
    const int request = Request(connection, "/binary");
    Require(sceHttpsSetSslVersion(request, 5) == 0);
    Require(sceHttpsSetMinSslVersion(request, 0) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0 && Read(request).size() == 1024);
    Require(sceHttpDeleteRequest(request) == 0);
}

static void Sni(int context, int connection, const char* url) {
    auto authority = Certificate(RootPem);
    auto* pointer = &authority;
    Require(sceHttpsLoadCert(context, 1, &pointer, nullptr, nullptr) == 0);
    int request = Request(connection, "/sni");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0 && Read(request) == "localhost");
    Require(sceHttpDeleteRequest(request) == 0);
    request = Request(connection, "/sni");
    Require(sceHttpsDisableOption(request, 0x80) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0 && Read(request).empty());
    Require(sceHttpDeleteRequest(request) == 0);
    auto wrong = std::string(url);
    wrong.replace(wrong.find("localhost"), 9, "127.0.0.1");
    request = sceHttpCreateRequestWithURL2(connection, "GET", wrong.c_str(), 0);
    Require(request > 0 && sceHttpsDisableOption(request, 0x80) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == Network);
    int error = 0;
    std::uint32_t detail = 0;
    Require(sceHttpsGetSslError(request, &error, &detail) == 0 && (detail & 4));
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

static void AuthParser() {
    auto challenges = HttpParseChallenges_nid_no_patch("Digest realm=\"a,b\\\"c\", nonce=\"n\", qop=\"auth-int,auth\", algorithm=SHA-256, Basic realm=\"fallback\"");
    Require(challenges.size() == 2 && challenges[0].type == 1 && challenges[1].type == 0);
    Require(challenges[0].parameters.at("realm") == "a,b\"c");
    Require(HttpAuthQuality_nid_no_patch(challenges[0]) == "auth");
    challenges = HttpParseChallenges_nid_no_patch("Negotiate token==, Basic realm=\"r\"   ");
    Require(challenges.size() == 1 && challenges[0].type == 0 && challenges[0].parameters.at("realm") == "r");
    for (const char* malformed : {" ", "Digest realm=\"unterminated", "Digest realm=\"escape\\", "Basic realm=a, REALM=b"})
        Require(HttpParseChallenges_nid_no_patch(malformed).empty());
    std::uint32_t state = 0x1d872b41;
    for (int index = 0; index < 5000; ++index) {
        state = state * 1664525U + 1013904223U;
        std::string input(state % 97, ' ');
        for (char& value : input) { state = state * 1664525U + 1013904223U; value = static_cast<char>(state >> 24); }
        for (const auto& challenge : HttpParseChallenges_nid_no_patch(input)) {
            Require(challenge.type == 0 || challenge.type == 1);
            for (const auto& [name, value] : challenge.parameters)
                Require(!name.empty() && name.size() + value.size() <= input.size());
        }
    }
}

struct AuthLog {
    int context;
    int connection;
    int decision = 0;
    int action = 0;
    int calls = 0;
    int type = 0;
    int needEntity = 0;
    std::string realm = "test realm";
    std::string entity;
    std::vector<std::pair<std::string, std::string>> saved;
};

static int APS5_VABI Authenticate(int request, int type, const char* realm, char* user, char* password,
    int needEntity, std::uint8_t** body, std::uint64_t* size, int* save, void* argument) {
    auto& log = *static_cast<AuthLog*>(argument);
    ++log.calls;
    Require(type == log.type && realm == log.realm);
    Require(needEntity == log.needEntity);
    log.saved.emplace_back(user, password);
    Require(sceHttpDeleteRequest(request) == static_cast<int>(0x80431021));
    Require(sceHttpTerm_nid_postfix(log.context) == static_cast<int>(0x80431021));
    int status = 0;
    Require(sceHttpGetStatusCode(request, &status) == 0 && (status == 401 || status == 407));
    std::snprintf(user, 256, "%s", "guest");
    std::snprintf(password, 256, "%s", log.action == 10 || (log.action == 12 && log.calls == 1) ? "wrong" : "secret");
    *save = 0;
    if (needEntity) {
        *body = reinterpret_cast<std::uint8_t*>(log.entity.data());
        *size = log.entity.size();
    }
    if (log.action == 3) std::memset(user, 'x', 256);
    if (log.action == 4) *save = 1;
    if (log.action == 5 || log.action == 6) { *body = nullptr; *size = UINT64_MAX; }
    if (log.action == 7) throw std::runtime_error("auth callback test");
    if (log.action == 8) Require(sceHttpAbortRequest(request) == 0);
    if (log.action == 9 && log.calls == 1) {
        const int nested = Request(log.connection, "/binary");
        Require(sceHttpSendRequest(nested, nullptr, 0) == 0 && Read(nested).size() == 1024);
        Require(sceHttpDeleteRequest(nested) == 0);
    }
    return log.decision;
}

struct AuthResult {
    int error;
    int status;
    std::string body;
};

static AuthResult SendAuth(AuthLog& log, const std::string& path, const char* method = "GET",
    const std::string& body = {}, bool enabled = true, bool callback = true) {
    log.calls = 0;
    log.saved.clear();
    const int request = path.starts_with("http") ? sceHttpCreateRequestWithURL2(log.connection, method, path.c_str(), body.size()) :
        Request(log.connection, path.c_str(), method, body.size());
    Require(request > 0 && sceHttpSetAuthEnabled(request, enabled ? 1 : 0) == 0);
    if (callback) Require(sceHttpSetAuthInfoCallback(request, Authenticate, &log) == 0);
    AuthResult result{sceHttpSendRequest(request, body.empty() ? nullptr : body.data(), body.size()), 0, {}};
    if (!result.error) {
        Require(sceHttpGetStatusCode(request, &result.status) == 0);
        result.body = Read(request);
    }
    Require(sceHttpDeleteRequest(request) == 0);
    return result;
}

static void AuthBasic(int context, int connection, const char* url, bool tls) {
    if (tls) {
        auto authority = Certificate(RootPem);
        auto* pointer = &authority;
        Require(sceHttpsLoadCert(context, 1, &pointer, nullptr, nullptr) == 0);
    }
    AuthLog log{context, connection};
    Require(sceHttpSetAuthEnabled(-1, 1) == InvalidId);
    Require(sceHttpSetAuthEnabled(connection, 2) == InvalidValue);
    Require(sceHttpAuthCacheFlush(-1) == InvalidId && sceHttpAuthCacheFlush(connection) == InvalidId);
    Require(sceHttpSetAuthInfoCallback(connection, Authenticate, &log) == 0);
    int inherited = Request(connection, "/auth/basic");
    Require(sceHttpSetAuthInfoCallback(connection, nullptr, nullptr) == 0);
    Require(sceHttpSendRequest(inherited, nullptr, 0) == 0 && Read(inherited) == "authenticated:");
    Require(sceHttpDeleteRequest(inherited) == 0);
    log.calls = 0;
    Require(sceHttpSetAuthInfoCallback(connection, Authenticate, &log) == 0);
    Require(sceHttpSetAuthEnabled(connection, 0) == 0);
    inherited = Request(connection, "/auth/basic");
    Require(sceHttpSetAuthEnabled(connection, 1) == 0);
    Require(sceHttpSetAuthInfoCallback(connection, nullptr, nullptr) == 0);
    Require(sceHttpSendRequest(inherited, nullptr, 0) == 0 && Read(inherited) == "authentication-required" && log.calls == 0);
    Require(sceHttpDeleteRequest(inherited) == 0);
    for (int decision : {INT32_MIN, -1, 0, 1, INT32_MAX}) {
        Require(sceHttpAuthCacheFlush(context) == 0);
        log.decision = decision;
        const auto result = SendAuth(log, "/auth/basic");
        Require(result.error == 0 && result.status == (decision < 0 ? 401 : 200));
        Require(result.body == (decision < 0 ? "authentication-required" : "authenticated:"));
        Require(log.calls == 1 && log.saved.front().first.empty() && log.saved.front().second.empty());
    }
    log.decision = 0;
    for (const char* method : {"HEAD", "OPTIONS", "DELETE", "TRACE"}) {
        const auto result = SendAuth(log, "/auth/basic", method);
        Require(result.error == 0 && result.status == 200 && result.body == (std::strcmp(method, "HEAD") == 0 ? "" : "authenticated:"));
    }
    auto extended = SendAuth(log, "/auth/basic?extraqop=auth-int", "POST", "payload");
    Require(extended.error == 0 && extended.status == 200 && extended.body == "authenticated:payload");
    auto result = SendAuth(log, "/auth/basic", "GET", {}, false);
    Require(result.error == 0 && result.status == 401 && log.calls == 0);
    result = SendAuth(log, "/auth/basic", "GET", {}, true, false);
    Require(result.error == 0 && result.status == 401 && log.calls == 0);
    for (int action : {3, 4, 6, 7, 8, 9, 10, 12}) {
        log.action = action;
        result = SendAuth(log, "/auth/basic");
        Require(result.error == (action == 3 || action == 4 ? InvalidValue : action == 7 ? Network : action == 8 ? Aborted : 0));
        if (!result.error) Require(result.status == (action == 10 ? 401 : 200));
        if (action == 10) Require(log.calls == 6);
        if (action == 12) Require(log.calls == 2 && log.saved.back().second == "wrong");
    }
    log.action = 7;
    std::string address(url);
    address.insert(address.find("://") + 3, "guest:secret@");
    result = SendAuth(log, address + "auth/basic");
    Require(result.error == 0 && result.status == 200 && log.calls == 0);
    if (!tls) {
        log.action = 0;
        log.decision = -1;
        result = SendAuth(log, address + "auth/basic-redirect");
        if (result.error || result.status != 401 || log.calls != 1)
            std::fprintf(stderr, "Cross-origin authentication: error=%08x status=%d callbacks=%d\n",
                static_cast<unsigned>(result.error), result.status, log.calls);
        Require(result.error == 0 && result.status == 401 && log.calls == 1);
        log.action = 7;
        log.decision = 0;
    }
    const int object = sceHttpCreateTemplate(context, "auth-url", 2, 0);
    const int authenticated = sceHttpCreateConnectionWithURL(object, address.c_str(), 0);
    Require(authenticated > 0);
    log.connection = authenticated;
    result = SendAuth(log, "/auth/basic");
    Require(result.error == 0 && result.status == 200 && log.calls == 0);
    result = SendAuth(log, "/auth/basic", "GET", {}, false);
    Require(result.error == 0 && result.status == 401 && log.calls == 0);
    Require(sceHttpDeleteConnection(authenticated) == 0 && sceHttpDeleteTemplate(object) == 0);
    log.connection = connection;
    log.action = 0;
    HttpEpollHandle epoll = nullptr;
    Require(sceHttpCreateEpoll(context, &epoll) == 0);
    const int request = Request(connection, "/auth/basic");
    Require(sceHttpSetAuthInfoCallback(request, Authenticate, &log) == 0);
    Require(sceHttpSetNonblock(request, 1) == 0 && sceHttpSetEpoll(request, epoll, nullptr) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(ReadAsync(request, epoll) == "authenticated:");
    Require(sceHttpDeleteRequest(request) == 0 && sceHttpDestroyEpoll(context, epoll) == 0);
}

static void AuthDigest(int context, int connection, bool tls) {
    if (tls) {
        auto authority = Certificate(RootPem);
        auto* pointer = &authority;
        Require(sceHttpsLoadCert(context, 1, &pointer, nullptr, nullptr) == 0);
    }
    AuthLog log{context, connection};
    log.type = 1;
    for (const char* algorithm : {"MD5", "MD5-sess", "SHA-256", "SHA-256-sess"}) {
        const auto path = std::string("/auth/digest?algorithm=") + algorithm;
        const auto result = SendAuth(log, path, "POST", "payload");
        Require(result.error == 0 && result.status == 200 && result.body == "authenticated:payload" && log.calls == 1);
    }
    log.needEntity = 1;
    log.entity = std::string("changed\0body", 12);
    for (const char* algorithm : {"MD5", "SHA-256-sess"}) {
        const auto path = std::string("/auth/digest?qop=auth-int&algorithm=") + algorithm;
        const auto result = SendAuth(log, path, "POST", "original");
        Require(result.error == 0 && result.status == 200 && result.body == "authenticated:" + log.entity);
    }
    for (bool chunked : {false, true}) {
        const int request = Request(connection, "/auth/digest?qop=auth-int", "POST", 8);
        Require(sceHttpSetAuthInfoCallback(request, Authenticate, &log) == 0);
        if (chunked) Require(sceHttpSetChunkedTransferEnabled(request, 1) == 0);
        else Require(sceHttpAddRequestHeader(request, "Content-Length", "8", 0) == 0);
        Require(sceHttpSendRequest(request, "original", 8) == 0 && Read(request) == "authenticated:" + log.entity);
        Require(sceHttpDeleteRequest(request) == 0);
    }
    log.action = 5;
    auto result = SendAuth(log, "/auth/digest?qop=auth-int", "POST", "original");
    Require(result.error == InvalidValue);
    log.action = 0;
    log.needEntity = 0;
    for (const char* algorithm : {"MD5", "MD5-sess", "SHA-256", "SHA-256-sess"}) {
        result = SendAuth(log, std::string("/auth/digest?qop=&algorithm=") + algorithm);
        Require(result.error == 0 && result.status == 200);
    }
    result = SendAuth(log, "/auth/digest?algorithm=SHA-256&userhash=true");
    Require(result.error == 0 && result.status == 200);
    result = SendAuth(log, "/auth/stale");
    Require(result.error == 0 && result.status == 200 && log.calls == 2);
    result = SendAuth(log, "/auth/multiple?algorithm=SHA-256");
    Require(result.error == 0 && result.status == 200 && log.type == 1);
    log.type = 0;
    log.realm = "fallback";
    result = SendAuth(log, "/auth/multiple?algorithm=unsupported");
    Require(result.error == 0 && result.status == 200 && log.calls == 1);
    log.type = 1;
    log.realm = "quoted \"realm\", value";
    result = SendAuth(log, "/auth/digest?realm=quoted%20%22realm%22%2C%20value");
    Require(result.error == 0 && result.status == 200);
    log.realm = "test realm";
    for (const char* path : {"/auth/malformed", "/auth/digest?algorithm=unsupported", "/auth/digest?qop=unsupported"}) {
        result = SendAuth(log, path);
        Require(result.error == 0 && result.status == 401 && log.calls == 0);
    }
}

static void AuthCache(int context, int connection, const char* url) {
    AuthLog log{context, connection};
    Require(sceHttpAuthCacheFlush(context) == 0);
    Require(SendAuth(log, "/auth/basic").status == 200);
    Require(log.saved.front().first.empty());
    Require(SendAuth(log, "/auth/basic").status == 200);
    Require(log.saved.front() == std::pair<std::string, std::string>("guest", "secret"));
    Require(sceHttpAuthCacheFlush(context) == 0);
    Require(SendAuth(log, "/auth/basic").status == 200 && log.saved.front().first.empty());
    Require(sceHttpAuthCacheFlush(context) == 0);
    for (int index = 0; index < 16; ++index) {
        log.realm = "realm-" + std::to_string(index);
        Require(SendAuth(log, "/auth/basic?realm=" + log.realm).status == 200 && log.saved.front().first.empty());
    }
    log.realm = "realm-0";
    Require(SendAuth(log, "/auth/basic?realm=" + log.realm).status == 200 && log.saved.front().first == "guest");
    log.realm = "realm-16";
    Require(SendAuth(log, "/auth/basic?realm=" + log.realm).status == 200);
    log.realm = "realm-0";
    Require(SendAuth(log, "/auth/basic?realm=" + log.realm).status == 200 && log.saved.front().first == "guest");
    log.realm = "realm-1";
    Require(SendAuth(log, "/auth/basic?realm=" + log.realm).status == 200 && log.saved.front().first.empty());
    const int other = sceHttpInit_nid_postfix(0, 0, 65536);
    const int object = sceHttpCreateTemplate(other, "auth-isolation", 2, 0);
    const int peer = sceHttpCreateConnectionWithURL(object, url, 0);
    AuthLog isolated{other, peer};
    isolated.realm = log.realm;
    Require(SendAuth(isolated, "/auth/basic?realm=" + isolated.realm).status == 200 && isolated.saved.front().first.empty());
    Require(SendAuth(log, "/auth/basic?realm=" + log.realm).status == 200 && log.saved.front().first == "guest");
    Require(sceHttpDeleteConnection(peer) == 0 && sceHttpDeleteTemplate(object) == 0);
    Require(sceHttpTerm_nid_postfix(other) == 0);
    std::vector<std::thread> workers;
    for (int index = 0; index < 4; ++index) workers.emplace_back([&, index] {
        AuthLog state{context, connection};
        state.type = 1;
        const auto data = "parallel-" + std::to_string(index);
        const auto result = SendAuth(state, "/auth/digest?algorithm=SHA-256", "POST", data);
        Require(result.error == 0 && result.status == 200 && result.body == "authenticated:" + data);
    });
    for (auto& worker : workers) worker.join();
}

static void AuthProxy(int context, int connection) {
    AuthLog log{context, connection};
    log.realm = "proxy";
    Require(sceHttpSetAuthInfoCallback(connection, Authenticate, &log) == 0);
    const int request = sceHttpCreateRequest(connection, 7, "authenticated.invalid:443", 0);
    Require(request > 0 && sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(Read(request).size() == 65536 && log.calls == 1);
    Require(sceHttpDeleteRequest(request) == 0);
    Require(sceHttpSetAuthInfoCallback(connection, nullptr, nullptr) == 0);
}

struct RedirectLog {
    int context;
    int decision;
    int method = -1;
    int action = 0;
    int calls = 0;
};

static int APS5_VABI RedirectDecision(int request, int status, std::int32_t* method, const char* location, void* argument) {
    auto& log = *static_cast<RedirectLog*>(argument);
    ++log.calls;
    Require(status >= 300 && status < 400 && location && method);
    int current = 0;
    char* headers = nullptr;
    std::size_t length = 0;
    Require(sceHttpGetStatusCode(request, &current) == 0 && current == status);
    Require(sceHttpGetAllResponseHeaders(request, &headers, &length) == 0);
    Require(std::string(headers, length).find("Location:") != std::string::npos);
    Require(sceHttpDeleteRequest(request) == static_cast<int>(0x80431021));
    Require(sceHttpTerm_nid_postfix(log.context) == static_cast<int>(0x80431021));
    if (log.method >= 0) *method = log.method;
    if (log.action == 1) throw std::runtime_error("redirect callback test");
    if (log.action == 2) Require(sceHttpAbortRequest(request) == 0);
    return log.decision;
}

static void RedirectCallbacks(int context, int connection, bool tls) {
    if (tls) {
        auto authority = Certificate(RootPem);
        auto* pointer = &authority;
        Require(sceHttpsLoadCert(context, 1, &pointer, nullptr, nullptr) == 0);
    }
    RedirectLog log{context, 0};
    Require(sceHttpSetRedirectCallback(connection, RedirectDecision, &log) == 0);
    for (int decision : {INT32_MIN, -1, 0, 1, INT32_MAX}) {
        log.decision = decision;
        log.calls = 0;
        const int request = Request(connection, "/redirect/302");
        Require(sceHttpSetAutoRedirect(request, 0) == 0);
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        const auto response = Read(request);
        if (response != (decision < 0 ? "discard" : "GET:"))
            std::fprintf(stderr, "redirect decision=%d body=%s size=%zu\n", decision, response.c_str(), response.size());
        Require(response == (decision < 0 ? "discard" : "GET:"));
        Require(log.calls == 1 && sceHttpDeleteRequest(request) == 0);
    }
    constexpr const char* names[] = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE", "CONNECT"};
    log.decision = 0;
    for (int method = 0; method < 8; ++method) {
        log.method = method;
        log.calls = 0;
        const int request = Request(connection, "/redirect/307");
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        const auto body = Read(request);
        if (method == 7) {
            Require(body.size() == 65536);
            for (std::size_t index = 0; index < body.size(); ++index)
                Require(static_cast<unsigned char>(body[index]) == index % 256);
        } else Require(body == (method == 2 ? std::string() : std::string(names[method]) + ':'));
        Require(log.calls == 1 && sceHttpDeleteRequest(request) == 0);
    }
    log.method = 4;
    int request = Request(connection, "/redirect/307", "POST", 7);
    Require(sceHttpSendRequest(request, "payload", 7) == 0 && Read(request) == "PUT:payload");
    Require(sceHttpDeleteRequest(request) == 0);
    log.method = 9;
    request = Request(connection, "/redirect/302");
    Require(sceHttpSendRequest(request, nullptr, 0) == InvalidValue);
    Require(sceHttpDeleteRequest(request) == 0);
    log.method = -1;
    log.calls = 0;
    request = Request(connection, "/loop");
    Require(sceHttpSendRequest(request, nullptr, 0) == Network && log.calls == 11);
    Require(sceHttpDeleteRequest(request) == 0);
    for (int action : {1, 2}) {
        log.action = action;
        request = Request(connection, "/redirect/302");
        Require(sceHttpSendRequest(request, nullptr, 0) == (action == 1 ? Network : Aborted));
        Require(sceHttpDeleteRequest(request) == 0);
    }
    Require(sceHttpSetRedirectCallback(connection, nullptr, nullptr) == 0);
}

struct CookieLog {
    int context;
    int connection;
    int decision;
    int action = 0;
    int calls = 0;
};

static int APS5_VABI ReceiveCookie(int request, const char* url, const char* header, std::uint64_t length, void* argument) {
    auto& log = *static_cast<CookieLog*>(argument);
    ++log.calls;
    Require(std::string(url).ends_with("/cookies/set"));
    Require(std::string(header, length).find('=') != std::string::npos);
    Require(sceHttpDeleteRequest(request) == static_cast<int>(0x80431021));
    Require(sceHttpTerm_nid_postfix(log.context) == static_cast<int>(0x80431021));
    if (log.action == 1) throw std::runtime_error("cookie callback test");
    if (log.action == 2 && log.calls == 1) {
        const int nested = Request(log.connection, "/cookies/check");
        Require(sceHttpSendRequest(nested, nullptr, 0) == 0 && Read(nested).empty());
        Require(sceHttpDeleteRequest(nested) == 0);
    }
    return log.decision;
}

static void CookieCallbacks(const char* url) {
    for (int decision : {INT32_MIN, -1, 0, 1, INT32_MAX}) {
        const int context = sceHttpInit_nid_postfix(0, 0, 65536);
        const int object = sceHttpCreateTemplate(context, "cookie-callback", 2, 0);
        CookieLog log{context, 0, decision};
        Require(sceHttpSetCookieEnabled(object, 1) == 0);
        Require(sceHttpSetCookieRecvCallback(object, ReceiveCookie, &log) == 0);
        const int connection = sceHttpCreateConnectionWithURL(object, url, 0);
        log.connection = connection;
        log.action = 2;
        int request = Request(connection, "/cookies/set");
        Require(sceHttpSetCookieRecvCallback(connection, nullptr, nullptr) == 0);
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        Read(request);
        Require(log.calls == 3);
        Require(sceHttpDeleteRequest(request) == 0);
        request = Request(connection, "/cookies/check");
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        Require(Read(request) == (decision < 0 ? "" : "session=alpha"));
        Require(sceHttpDeleteRequest(request) == 0);
        log.action = 1;
        log.calls = 0;
        request = Request(connection, "/cookies/set");
        Require(sceHttpSetCookieRecvCallback(request, ReceiveCookie, &log) == 0);
        Require(sceHttpSendRequest(request, nullptr, 0) == Network);
        Require(log.calls == 1);
        Require(sceHttpDeleteRequest(request) == 0);
        log.action = 0;
        log.calls = 0;
        request = Request(connection, "/cookies/set");
        Require(sceHttpSetCookieRecvCallback(request, ReceiveCookie, &log) == 0);
        Require(sceHttpSetCookieEnabled(request, 0) == 0);
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        Read(request);
        Require(log.calls == 0);
        Require(sceHttpDeleteRequest(request) == 0);
        Require(sceHttpDeleteConnection(connection) == 0 && sceHttpDeleteTemplate(object) == 0);
        Require(sceHttpTerm_nid_postfix(context) == 0);
    }
}

struct StatusLog {
    int context = 0;
    int connection = 0;
    int action = 0;
    int request = 0;
    std::vector<int> phases;
};

static void APS5_VABI RequestStatus(int request, int phase, void* argument) {
    auto& log = *static_cast<StatusLog*>(argument);
    Require(phase >= 0 && phase <= 10);
    Require(!log.request || request == log.request);
    log.phases.push_back(phase);
    Require(sceHttpDeleteRequest(request) == static_cast<int>(0x80431021));
    Require(sceHttpSendRequest(request, nullptr, 0) == static_cast<int>(0x80431021));
    char byte = 0;
    Require(sceHttpReadData(request, &byte, 1) == static_cast<int>(0x80431021));
    Require(sceHttpTerm_nid_postfix(log.context) == static_cast<int>(0x80431021));
    if (phase == 10) {
        int status = 0;
        Require(sceHttpGetStatusCode(request, &status) == 0 && status == 200);
    }
    if (phase == 7 && log.action == 1) Require(sceHttpAbortRequest(request) == 0);
    if (phase == 0 && log.action == 2) throw std::runtime_error("status callback test");
    if (phase == 4 && log.action == 3) Require(sceHttpSetRequestStatusCallback(request, nullptr, nullptr) == 0);
    if (phase == 7 && log.action == 4) {
        const int nested = Request(log.connection, "/binary");
        Require(sceHttpSetRequestStatusCallback(nested, nullptr, nullptr) == 0);
        Require(sceHttpSendRequest(nested, nullptr, 0) == 0 && Read(nested).size() == 1024);
        Require(sceHttpDeleteRequest(nested) == 0);
    }
}

static void StatusCallbacks(int context, int connection, bool tls) {
    if (tls) {
        auto authority = Certificate(RootPem);
        auto* pointer = &authority;
        Require(sceHttpsLoadCert(context, 1, &pointer, nullptr, nullptr) == 0);
    }
    StatusLog log{context, connection};
    Require(sceHttpSetRequestStatusCallback(connection, RequestStatus, &log) == 0);
    int request = Request(connection, "/binary");
    log.request = request;
    Require(sceHttpSetRequestStatusCallback(connection, nullptr, nullptr) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0 && Read(request).size() == 1024);
    const std::vector<int> expected = tls ? std::vector<int>{0,1,2,3,4,5,6,7,8,9,10} : std::vector<int>{0,1,2,3,4,7,8,9,10};
    if (log.phases != expected) {
        for (int phase : log.phases) std::fprintf(stderr, "%d ", phase);
        std::fprintf(stderr, "\n");
    }
    Require(log.phases == expected);
    Require(sceHttpDeleteRequest(request) == 0);
    for (int action = 1; action <= 4; ++action) {
        log.phases.clear();
        log.action = action;
        request = Request(connection, "/binary");
        log.request = request;
        Require(sceHttpSetRequestStatusCallback(request, RequestStatus, &log) == 0);
        const int result = sceHttpSendRequest(request, nullptr, 0);
        Require(result == (action == 1 ? Aborted : action == 2 ? Network : 0));
        if (action >= 3) Require(Read(request).size() == 1024);
        if (action == 2) {
            Require(log.phases == std::vector<int>{0});
            int error = -1;
            std::uint32_t detail = 1;
            Require(sceHttpsGetSslError(request, &error, &detail) == 0 && error == 0 && detail == 0);
        }
        if (action == 3) Require(log.phases.back() == 4);
        Require(sceHttpDeleteRequest(request) == 0);
    }
    log.phases.clear();
    log.action = 0;
    HttpEpollHandle epoll = nullptr;
    Require(sceHttpCreateEpoll(context, &epoll) == 0);
    request = Request(connection, "/binary");
    log.request = request;
    Require(sceHttpSetRequestStatusCallback(request, RequestStatus, &log) == 0);
    Require(sceHttpSetNonblock(request, 1) == 0 && sceHttpSetEpoll(request, epoll, nullptr) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(ReadAsync(request, epoll).size() == 1024);
    Require(log.phases == expected);
    Require(sceHttpDeleteRequest(request) == 0 && sceHttpDestroyEpoll(context, epoll) == 0);
    log.phases.clear();
    const std::string invalidHost(64, 'a');
    const int failedTemplate = sceHttpCreateTemplate(context, "status-failure", 2, 0);
    Require(failedTemplate > 0);
    const int failedConnection = sceHttpCreateConnectionWithURL(
        failedTemplate, ("http://" + invalidHost + ".invalid/").c_str(), 0);
    Require(failedConnection > 0);
    Require(sceHttpSetResolveTimeOut(failedConnection, 10000) == 0);
    Require(sceHttpSetResolveRetry(failedConnection, 2) == 0);
    request = Request(failedConnection, "/");
    log.request = request;
    Require(sceHttpSetRequestStatusCallback(request, RequestStatus, &log) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == Network);
    Require(log.phases == std::vector<int>({0,1,0,1,0,1}));
    Require(sceHttpDeleteRequest(request) == 0 && sceHttpDeleteConnection(failedConnection) == 0);
    Require(sceHttpDeleteTemplate(failedTemplate) == 0);
    if (tls) {
        log.phases.clear();
        Require(sceHttpsUnloadCert(context) == 0);
        request = Request(connection, "/binary");
        log.request = request;
        Require(sceHttpSetRequestStatusCallback(request, RequestStatus, &log) == 0);
        Require(sceHttpSendRequest(request, nullptr, 0) == Network);
        Require(log.phases == std::vector<int>({0,1,2,3,4,5}));
        Require(sceHttpDeleteRequest(request) == 0);
    }
}

static void Phases(int object, int connection, const char* url) {
    Require(sceHttpSetResolveRetry(connection, -1) == InvalidValue);
    Require(sceHttpSetResolveTimeOut(connection, 0) == InvalidValue);
    Require(sceHttpSetSendTimeOut(connection, 0) == InvalidValue);
    Require(sceHttpSetResolveRetry(-1, 1) == InvalidId);
    Require(sceHttpSetResolveTimeOut(-1, 10000) == InvalidId);
    Require(sceHttpSetSendTimeOut(-1, 10000) == InvalidId);
    int request = Request(connection, "/slow");
    Require(sceHttpSetSendTimeOut(request, 10000) == 0);
    Require(sceHttpSetRecvTimeOut(request, 1000000) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(Read(request) == std::string("hello\0world", 11));
    Require(sceHttpDeleteRequest(request) == 0);
    request = Request(connection, "/stall-upload", "POST", 16 * 1024 * 1024);
    Require(sceHttpSetSendTimeOut(request, 20000) == 0);
    Require(sceHttpSetRecvTimeOut(request, 1000000) == 0);
    const std::string upload(16 * 1024 * 1024, 'u');
    Require(sceHttpSendRequest(request, upload.data(), upload.size()) == Network);
    Require(sceHttpDeleteRequest(request) == 0);
    request = Request(connection, "/release-upload");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Read(request);
    Require(sceHttpDeleteRequest(request) == 0);
    auto host = std::string(url);
    host.replace(host.find("127.0.0.1"), 9, "localhost");
    const int named = sceHttpCreateConnectionWithURL(object, host.c_str(), 0);
    Require(named > 0);
    Require(sceHttpSetResolveRetry(named, 2) == 0);
    Require(sceHttpSetResolveTimeOut(named, 1000000) == 0);
    request = Request(named, "/binary");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(Read(request).size() == 1024);
    Require(sceHttpDeleteRequest(request) == 0);
    Require(sceHttpDeleteConnection(named) == 0);
    host.replace(host.find("localhost"), 9, std::string(64, 'a') + ".invalid");
    const int invalid = sceHttpCreateConnectionWithURL(object, host.c_str(), 0);
    Require(invalid > 0);
    Require(sceHttpSetResolveRetry(invalid, 2) == 0);
    Require(sceHttpSetResolveTimeOut(invalid, 100000) == 0);
    request = Request(invalid, "/binary");
    Require(sceHttpSendRequest(request, nullptr, 0) == Network);
    Require(sceHttpDeleteRequest(request) == 0);
    Require(sceHttpDeleteConnection(invalid) == 0);
}

struct VerificationState {
    int ssl;
    int http;
    int request = 0;
    int calls = 0;
    std::uint32_t errors = 0;
    bool reject = false;
    bool exception = false;
    bool abort = false;
    int connection = 0;
    bool nested = false;
};

static int APS5_VABI NestedVerification(int, unsigned, void* const*, int, void* argument) {
    auto& state = *static_cast<VerificationState*>(argument);
    constexpr int busy = static_cast<int>(0x80431021);
    Require(sceHttpDeleteRequest(state.request) == busy);
    Require(sceHttpTerm_nid_postfix(state.http) == busy);
    char byte;
    Require(sceHttpReadData(state.request, &byte, 1) == busy);
    Require(sceHttpSendRequest(state.request, nullptr, 0) == busy);
    return 0;
}

static int APS5_VABI VerifyTls(int ssl, unsigned flags, void* const* certificates, int count, void* argument) {
    auto& state = *static_cast<VerificationState*>(argument);
    Require(ssl == state.ssl && count > 0 && certificates);
    ++state.calls;
    state.errors = flags;
    for (int i = 0; i < count; ++i) {
        void* name = sceSslGetSubjectName(ssl, certificates[i]);
        Require(name && sceSslGetNameEntryCount(ssl, name) > 0);
        Require(sceSslFreeSslCertName(ssl, name) == 0);
    }
    constexpr int busy = static_cast<int>(0x80431021);
    Require(sceHttpDeleteRequest(state.request) == busy);
    Require(sceHttpTerm_nid_postfix(state.http) == busy);
    char byte;
    Require(sceHttpReadData(state.request, &byte, 1) == busy);
    int status = 0;
    Require(sceHttpGetStatusCode(state.request, &status) < 0);
    if (state.nested) {
        const int request = Request(state.connection, "/binary");
        Require(sceHttpSetNonblock(request, 0) == 0);
        Require(sceHttpsSetSslCallback(request, NestedVerification, &state) == 0);
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        Require(Read(request).size() == 1024);
        Require(sceHttpDeleteRequest(request) == 0);
    }
    if (state.abort) Require(sceHttpAbortRequest(state.request) == 0);
    if (state.exception) throw std::runtime_error("TLS verification callback failure");
    return state.reject ? -1 : 0;
}

static void Verification(const char* url) {
    const int ssl = sceSslInit_nid_postfix(1048576);
    const int http = sceHttpInit_nid_postfix(0, ssl, 65536);
    const int object = sceHttpCreateTemplate(http, "verify callback", 2, 0);
    VerificationState state{ssl, http};
    Require(sceHttpsSetSslCallback(object, VerifyTls, &state) == 0);
    const int connection = sceHttpCreateConnectionWithURL(object, url, 0);
    int error = 0;
    std::uint32_t detail = 0;
    for (bool reject : {false, true}) {
        state.reject = reject;
        state.calls = 0;
        state.request = Request(connection, "/binary");
        Require(sceHttpSendRequest(state.request, nullptr, 0) == (reject ? Network : 0));
        Require(state.calls == 1 && (state.errors & 32));
        if (!reject) {
            Require(Read(state.request).size() == 1024);
            Require(sceHttpsGetSslError(state.request, &error, &detail) == 0 && error == 0 && detail == 0);
        }
        Require(sceHttpDeleteRequest(state.request) == 0);
    }
    auto authority = Certificate(RootPem);
    auto* pointer = &authority;
    Require(sceHttpsLoadCert(http, 1, &pointer, nullptr, nullptr) == 0);
    state.reject = false;
    state.exception = true;
    state.request = Request(connection, "/binary");
    Require(sceHttpSendRequest(state.request, nullptr, 0) == Network);
    Require(sceHttpsGetSslError(state.request, &error, &detail) == 0 && error == static_cast<int>(0x80435063) && detail == 1);
    Require(sceHttpDeleteRequest(state.request) == 0);
    state.exception = false;
    state.abort = true;
    state.request = Request(connection, "/binary");
    Require(sceHttpSendRequest(state.request, nullptr, 0) == Aborted);
    Require(sceHttpDeleteRequest(state.request) == 0);
    state.abort = false;
    state.calls = 0;
    state.connection = connection;
    state.nested = true;
    HttpEpollHandle epoll = nullptr;
    Require(sceHttpCreateEpoll(http, &epoll) == 0);
    Require(sceHttpSetNonblock(connection, 1) == 0);
    Require(sceHttpSetEpoll(connection, epoll, nullptr) == 0);
    state.request = Request(connection, "/binary");
    Require(sceHttpSendRequest(state.request, nullptr, 0) == 0);
    Require(ReadAsync(state.request, epoll).size() == 1024);
    Require(state.calls == 1 && state.errors == 0);
    Require(sceHttpDeleteRequest(state.request) == 0);
    SceSsl::MemoryPoolStats stats{};
    Require(sceSslGetMemoryPoolStats(ssl, &stats) == 0 && stats.currentInuseSize == 0);
    Require(sceHttpTerm_nid_postfix(http) == 0);
    Require(sceSslTerm_nid_postfix(ssl) == 0);
}

static void AutoProxy(int context, const char* url) {
    Require(sceHttpCreateTemplate(context, "test", 2, 2) == InvalidValue);
    const int object = sceHttpCreateTemplate(context, "test", 2, 1);
    Require(object > 0);
    const int connection = sceHttpCreateConnectionWithURL(object, url, 0);
    Require(connection > 0);
    const int request = Request(connection, "/binary");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(Read(request).size() == 1024);
    Require(sceHttpDeleteRequest(request) == 0);
    Require(sceHttpDeleteConnection(connection) == 0);
    Require(sceHttpDeleteTemplate(object) == 0);
}

static void Authorities() {
    const int ssl = sceSslInit_nid_postfix(1048576);
    const int http = sceHttpInit_nid_postfix(0, ssl, 65536);
    Require(ssl > 0 && http > 0);
    SceSsl::CaList list{};
    Require(sceHttpsGetCaList(http, &list) == 0 && !list.certs && !list.num);
    Require(sceHttpsGetCaList(http, nullptr) == InvalidValue);
    Require(sceHttpsGetCaList(-1, &list) == InvalidId);
    auto authority = Certificate(RootPem);
    SceSsl::Data* authorities[] = {&authority, &authority};
    Require(sceHttpsLoadCert(http, 2, authorities, nullptr, nullptr) == 0);
    Require(sceHttpsGetCaList(http, &list) == 0 && list.certs && list.num == 2);
    Require(sceHttpsLoadCert(http, 1, authorities, nullptr, nullptr) == 0);
    SceSsl::CaList added{};
    Require(sceHttpsGetCaList(http, &added) == 0 && added.num == 3);
    Require(sceHttpsFreeCaList(http, &added) == 0);
    for (int i = 0; i < list.num; ++i) {
        void* name = sceSslGetSubjectName(ssl, list.certs[i]);
        Require(name && sceSslGetNameEntryCount(ssl, name) > 0);
        Require(sceSslFreeSslCertName(ssl, name) == 0);
    }
    SceSsl::MemoryPoolStats stats{};
    Require(sceSslGetMemoryPoolStats(ssl, &stats) == 0 && stats.currentInuseSize > 0);
    Require(sceHttpsUnloadCert(http) == 0);
    void* name = sceSslGetSubjectName(ssl, list.certs[0]);
    Require(name && sceSslFreeSslCertName(ssl, name) == 0);
    auto wrong = list;
    ++wrong.num;
    Require(sceHttpsFreeCaList(http, &wrong) == InvalidValue);
    const int other = sceHttpInit_nid_postfix(0, ssl, 65536);
    Require(sceHttpsFreeCaList(other, &list) == InvalidValue);
    Require(sceHttpTerm_nid_postfix(other) == 0);
    Require(sceHttpsFreeCaList(http, &list) == 0 && !list.certs && !list.num);
    Require(sceSslGetMemoryPoolStats(ssl, &stats) == 0 && stats.currentInuseSize == 0);
    Require(sceHttpsLoadCert(http, 1, authorities, nullptr, nullptr) == 0);
    Require(sceHttpsGetCaList(http, &list) == 0 && list.num == 1);
    Require(sceHttpTerm_nid_postfix(http) == 0);
    Require(sceSslGetMemoryPoolStats(ssl, &stats) == 0 && stats.currentInuseSize == 0);
    Require(sceSslTerm_nid_postfix(ssl) == 0);
}

static void Framing(int connection) {
    for (const char* name : {"Content-Length", "Transfer-Encoding"}) {
        const int request = Request(connection, "/echo", "POST");
        Require(sceHttpAddRequestHeader(request, name, std::strcmp(name, "Content-Length") == 0 ? "7, 7" : "ChUnKeD", 0) == 0);
        Require(sceHttpSendRequest(request, "payload", 7) == 0);
        Require(Read(request) == "payload");
        Require(sceHttpDeleteRequest(request) == 0);
    }
    int request = Request(connection, "/echo", "POST");
    Require(sceHttpAddRequestHeader(request, "Content-Length", "7", 0) == 0);
    Require(sceHttpAddRequestHeader(request, "Content-Length", "7", 1) == 0);
    Require(sceHttpSendRequest(request, "payload", 7) == 0);
    Require(Read(request) == "payload");
    Require(sceHttpDeleteRequest(request) == 0);
    for (const char* value : {"", "8", "-1", "7,8", "7,", "18446744073709551616", "seven"}) {
        request = Request(connection, "/echo", "POST", 7);
        Require(sceHttpAddRequestHeader(request, "Content-Length", value, 0) == 0);
        Require(sceHttpSendRequest(request, "payload", 7) == InvalidValue);
        Require(sceHttpDeleteRequest(request) == 0);
    }
    for (const char* value : {"", "identity", "chunked,gzip", "chunked,chunked", "gzip,"}) {
        request = Request(connection, "/echo", "POST", 7);
        Require(sceHttpAddRequestHeader(request, "Transfer-Encoding", value, 0) == 0);
        Require(sceHttpSendRequest(request, "payload", 7) == InvalidValue);
        Require(sceHttpDeleteRequest(request) == 0);
    }
    request = Request(connection, "/echo", "POST", 7);
    Require(sceHttpAddRequestHeader(request, "Content-Length", "7", 0) == 0);
    Require(sceHttpAddRequestHeader(request, "Transfer-Encoding", "chunked", 0) == 0);
    Require(sceHttpSendRequest(request, "payload", 7) == InvalidValue);
    Require(sceHttpDeleteRequest(request) == 0);
}

static void Tunnel(int context, int connection, bool secure) {
    if (secure) {
        const int untrusted = Request(connection, "destination.invalid:443", "CONNECT");
        Require(sceHttpSendRequest(untrusted, nullptr, 0) == Network);
        Require(sceHttpDeleteRequest(untrusted) == 0);
        auto authority = Certificate(RootPem);
        auto* pointer = &authority;
        Require(sceHttpsLoadCert(context, 1, &pointer, nullptr, nullptr) == 0);
    }
    Require(sceHttpCreateRequest2(connection, "CONNECT", "bad/target:443", 0) == static_cast<int>(0x80433060));
    Require(sceHttpCreateRequest2(connection, "CONNECT", "target.invalid:0", 0) == static_cast<int>(0x80433060));
    Require(sceHttpCreateRequest2(connection, "CONNECT", "target.invalid:443", 1) == InvalidValue);
    for (int i = 0; i < 4; ++i) {
        const int request = i == 0 ? sceHttpCreateRequest2(connection, "CONNECT", "destination.invalid:443", 0) :
            i == 1 ? sceHttpCreateRequest(connection, 7, "destination.invalid:443", 0) :
            i == 2 ? sceHttpCreateRequestWithURL2(connection, "CONNECT", "https://destination.invalid/path", 0) :
                     sceHttpCreateRequestWithURL(connection, 7, "https://destination.invalid/path", 0);
        Require(request > 0);
        Require(sceHttpSendRequest(request, nullptr, 0) == 0);
        int status = 0;
        Require(sceHttpGetStatusCode(request, &status) == 0 && status == 200);
        char* headers = nullptr;
        std::size_t headerSize = 0;
        Require(sceHttpGetAllResponseHeaders(request, &headers, &headerSize) == 0);
        Require(std::string(headers, headerSize).find("X-Tunnel-Target: destination.invalid:443") != std::string::npos);
        int result = 0;
        std::uint64_t length = 123;
        Require(sceHttpGetResponseContentLength(request, &result, &length) == 0 && result == static_cast<int>(0x80431071));
        const auto bytes = Read(request);
        Require(bytes.size() == 65536);
        for (std::size_t n = 0; n < bytes.size(); ++n) Require(static_cast<unsigned char>(bytes[n]) == n % 256);
        Require(sceHttpDeleteRequest(request) == 0);
    }
    int request = Request(connection, "rejected.invalid:443", "CONNECT");
    Require(sceHttpSendRequest(request, nullptr, 0) == Network);
    if (secure) {
        int error = 0;
        std::uint32_t detail = 1;
        Require(sceHttpsGetSslError(request, &error, &detail) == 0 && error == static_cast<int>(0x80435064) && detail == 0);
    }
    Require(sceHttpDeleteRequest(request) == 0);
    HttpEpollHandle epoll = nullptr;
    Require(sceHttpCreateEpoll(context, &epoll) == 0);
    Require(sceHttpSetEpoll(connection, epoll, nullptr) == 0);
    Require(sceHttpSetNonblock(connection, 1) == 0);
    request = Request(connection, "destination.invalid:443", "CONNECT");
    Require(sceHttpSendRequest(request, nullptr, 0) == 0);
    Require(ReadAsync(request, epoll).size() == 65536);
    Require(sceHttpDeleteRequest(request) == 0);
    Require(sceHttpDestroyEpoll(context, epoll) == 0);
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
    else if (mode == "framing") Framing(connection);
    else if (mode == "cookie_callbacks") CookieCallbacks(argv[1]);
    else if (mode == "redirect_callbacks" || mode == "redirect_callbacks_tls") RedirectCallbacks(context, connection, mode == "redirect_callbacks_tls");
    else if (mode == "auth_basic" || mode == "auth_basic_tls") AuthBasic(context, connection, argv[1], mode == "auth_basic_tls");
    else if (mode == "auth_digest" || mode == "auth_digest_tls") AuthDigest(context, connection, mode == "auth_digest_tls");
    else if (mode == "auth_cache") AuthCache(context, connection, argv[1]);
    else if (mode == "auth_proxy") AuthProxy(context, connection);
    else if (mode == "auth_parser") AuthParser();
    else if (mode == "status" || mode == "status_tls") StatusCallbacks(context, connection, mode == "status_tls");
    else if (mode == "authorities") Authorities();
    else if (mode == "auto_proxy") AutoProxy(context, argv[1]);
    else if (mode == "verification") Verification(argv[1]);
    else if (mode == "phases") Phases(object, connection, argv[1]);
    else if (mode == "tunnel" || mode == "tunnel_tls") Tunnel(context, connection, mode == "tunnel_tls");
    else if (mode == "async") Async(context, connection, argv[1]);
    else if (mode == "async_tls") AsyncTls(context, connection);
    else if (mode == "tls" || mode == "mutual") Tls(context, connection, argv[1], mode == "mutual");
    else if (mode == "expired") Expired(context, connection);
    else if (mode == "sni") Sni(context, connection, argv[1]);
    else if (mode == "minimum12" || mode == "minimum13") MinimumVersion(context, connection);
    else if (mode == "lifecycle") { Lifecycle(context, connection); return 0; }
    else if (mode == "contexts") { Contexts(context, connection, argv[1]); return 0; }
    else Require(false);
    Require(sceHttpDeleteConnection(connection) == 0);
    Require(sceHttpDeleteTemplate(object) == 0);
    Require(sceHttpTerm_nid_postfix(context) == 0);
}
