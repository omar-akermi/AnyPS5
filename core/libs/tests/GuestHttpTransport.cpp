#include "prx/libc/include/general/VabiMacros.hpp"
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
int APS5_VABI sceHttpSetAutoRedirect(int, int);
int APS5_VABI sceHttpSetInflateGZIPEnabled(int, int);
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
    Require(Unsupported([&] { sceHttpSendRequest(secure, nullptr, 0); }));
    Require(sceHttpDeleteRequest(secure) == 0);
    int request = Request(connection, "/headers");
    Require(Unsupported([&] { sceHttpSetNonblock(request, 1); }));
    Require(Unsupported([&] { sceHttpSetAutoRedirect(request, 1); }));
    Require(Unsupported([&] { sceHttpSetInflateGZIPEnabled(request, 1); }));
    Require(sceHttpSetResponseHeaderMaxSize(request, 64) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) < 0);
    Require(sceHttpDeleteRequest(request) == 0);
    request = Request(connection, "/slow");
    Require(sceHttpSetRecvTimeOut(request, 50000) == 0);
    Require(sceHttpSendRequest(request, nullptr, 0) == Network);
    Require(sceHttpDeleteRequest(request) == 0);
    for (const char* path : {"/truncated", "/badchunk"}) {
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
    else if (mode == "lifecycle") { Lifecycle(context, connection); return 0; }
    else if (mode == "contexts") { Contexts(context, connection, argv[1]); return 0; }
    else Require(false);
    Require(sceHttpDeleteConnection(connection) == 0);
    Require(sceHttpDeleteTemplate(object) == 0);
    Require(sceHttpTerm_nid_postfix(context) == 0);
}
