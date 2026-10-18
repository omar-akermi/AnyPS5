#include <cstdint>
#include <cstddef>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
#include "SceTypes.hpp"
#include "prx/libc/include/General.hpp"
#include "prx/libSceHttp/src/HttpErrors.hpp"
#include "prx/libSceHttp/src/Transport.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

static std::atomic<int> g_nextHandle{1};
using HttpRequestStatusCallback = void (APS5_VABI *)(int, int, void*);
struct RequestStatusRegistration {
    HttpRequestStatusCallback callback;
    void* argument;
};
static std::mutex g_statusMutex;
static std::map<int, RequestStatusRegistration> g_statusCallbacks;
struct HttpsCaList {
    void* certs;
    int certsNum;
};

#ifdef _WIN32
struct HostMutex {
    SRWLOCK native = SRWLOCK_INIT;

    HostMutex() = default;
    HostMutex(const HostMutex&) = delete;
    HostMutex& operator=(const HostMutex&) = delete;

    void lock() { AcquireSRWLockExclusive(&native); }
    void unlock() { ReleaseSRWLockExclusive(&native); }
};
#else
using HostMutex = std::mutex;
#endif

class HostCondition {
public:
    HostCondition() = default;
    HostCondition(const HostCondition&) = delete;
    HostCondition& operator=(const HostCondition&) = delete;

    void NotifyAll() {
#ifdef _WIN32
        WakeAllConditionVariable(&native);
#else
        native.notify_all();
#endif
    }

    void Wait(std::unique_lock<HostMutex>& lock) {
#ifdef _WIN32
        if (!SleepConditionVariableSRW(&native, &lock.mutex()->native, INFINITE, 0))
            throw std::runtime_error("libSceHttp: native condition wait failed");
#else
        native.wait(lock);
#endif
    }

    void WaitUntil(std::unique_lock<HostMutex>& lock, std::chrono::steady_clock::time_point deadline) {
#ifdef _WIN32
        const auto now = std::chrono::steady_clock::now();
        if (deadline <= now) return;
        const auto milliseconds = std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count();
        if (!SleepConditionVariableSRW(&native, &lock.mutex()->native, static_cast<DWORD>(milliseconds), 0) &&
            GetLastError() != ERROR_TIMEOUT)
            throw std::runtime_error("libSceHttp: native condition wait failed");
#else
        native.wait_until(lock, deadline);
#endif
    }

private:
#ifdef _WIN32
    CONDITION_VARIABLE native = CONDITION_VARIABLE_INIT;
#else
    std::condition_variable native;
#endif
};

struct HttpEpoll : HttpEventSink {
    struct Entry {
        HttpNBEvent event;
        std::weak_ptr<std::atomic<bool>> alive;
    };
    HostMutex mutex;
    HostCondition wake;
    bool aborted = false;
    bool destroyed = false;
    bool exhausted = false;
    std::deque<Entry> events;

    explicit HttpEpoll(int context) : HttpEventSink(context) {}

    void Notify(HttpNBEvent event, std::weak_ptr<std::atomic<bool>> alive) noexcept override {
        std::lock_guard lock(mutex);
        if (destroyed || aborted) return;
        std::erase_if(events, [](const auto& entry) {
            const auto token = entry.alive.lock();
            return !token || !token->load();
        });
        for (auto& entry : events) {
            if (entry.alive.lock() == alive.lock() && entry.event.id == event.id) {
                entry.event.events |= event.events;
                entry.event.eventDetail |= event.eventDetail;
                wake.NotifyAll();
                return;
            }
        }
        try { events.push_back({event, std::move(alive)}); }
        catch (const std::bad_alloc&) { exhausted = true; }
        wake.NotifyAll();
    }
};

static std::mutex g_stateMutex;
static std::unordered_set<int> g_contexts;
static std::unordered_map<HttpEpollHandle, std::shared_ptr<HttpEpoll>> g_epolls;

static std::shared_ptr<HttpEpoll> FindEpoll(HttpEpollHandle eh) {
    const auto it = g_epolls.find(eh);
    return it == g_epolls.end() ? nullptr : it->second;
}

static void MarkDestroyed(HttpEpoll& epoll) {
    std::lock_guard lock(epoll.mutex);
    epoll.destroyed = true;
    epoll.wake.NotifyAll();
}

int HttpNextHandle_nid_no_patch() { return g_nextHandle.fetch_add(1, std::memory_order_relaxed); }

void HttpForgetCallback_nid_no_patch(int id) {
    std::lock_guard lock(g_statusMutex);
    g_statusCallbacks.erase(id);
}

bool HttpHasCallback_nid_no_patch(int id) {
    std::lock_guard lock(g_statusMutex);
    return g_statusCallbacks.contains(id);
}

extern "C" {

int APS5_VABI sceHttpCreateEpoll(int http_ctx_id, HttpEpollHandle* eh) {
    std::lock_guard lock(g_stateMutex);
    if (g_contexts.empty()) return ERROR_BEFORE_INIT;
    if (!g_contexts.contains(http_ctx_id)) return ERROR_INVALID_ID;
    if (!eh) return ERROR_INVALID_VALUE;
    auto epoll = std::make_shared<HttpEpoll>(http_ctx_id);
    *eh = epoll.get();
    g_epolls.emplace(epoll.get(), std::move(epoll));
    return 0;
}

int APS5_VABI sceHttpDestroyEpoll(int http_ctx_id, HttpEpollHandle eh) {
    std::shared_ptr<HttpEpoll> epoll;
    {
        std::lock_guard lock(g_stateMutex);
        if (g_contexts.empty()) return ERROR_BEFORE_INIT;
        if (!g_contexts.contains(http_ctx_id)) return ERROR_INVALID_ID;
        if (!eh) return ERROR_INVALID_VALUE;
        epoll = FindEpoll(eh);
        if (!epoll) return ERROR_INVALID_ID;
        if (epoll->Context() != http_ctx_id) return ERROR_INVALID_ID;
        g_epolls.erase(eh);
    }
    MarkDestroyed(*epoll);
    return 0;
}

int APS5_VABI sceHttpInit_nid_postfix(int memid, int ssl_ctx_id, uint64_t pool_size) {
    (void)memid;
    (void)ssl_ctx_id;
    (void)pool_size;
    const int id = g_nextHandle.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard lock(g_stateMutex);
    HttpContextStarted_nid_no_patch(id);
    g_contexts.insert(id);
    return id;
}

int APS5_VABI sceHttpSetAuthEnabled(int id, int enable) {
    if (HttpHasObject_nid_no_patch(id) && (enable != 0)) NotImplemented_nid_no_patch(__func__);
    (void)id;
    (void)enable;
    return 0;
}

int APS5_VABI sceHttpSetAuthInfoCallback(int id, HttpAuthInfoCallback callback, void* userArg) {
    if (HttpHasObject_nid_no_patch(id) && (callback != nullptr)) NotImplemented_nid_no_patch(__func__);
    (void)id;
    (void)callback;
    (void)userArg;
    return 0;
}

int APS5_VABI sceHttpSetEpoll(int id, HttpEpollHandle eh, void* user_arg) {
    std::shared_ptr<HttpEpoll> epoll;
    {
        std::lock_guard lock(g_stateMutex);
        if (g_contexts.empty()) return ERROR_BEFORE_INIT;
        epoll = FindEpoll(eh);
        if (!epoll) return ERROR_INVALID_ID;
    }
    return HttpBindEpoll_nid_no_patch(id, std::move(epoll), eh, user_arg);
}

int APS5_VABI sceHttpSetResolveRetry(int id, int32_t retry) {
    if (HttpHasObject_nid_no_patch(id)) NotImplemented_nid_no_patch(__func__);
    (void)id;
    (void)retry;
    return 0;
}

int APS5_VABI sceHttpSetResolveTimeOut(int id, uint32_t usec) {
    if (HttpHasObject_nid_no_patch(id)) NotImplemented_nid_no_patch(__func__);
    (void)id;
    (void)usec;
    return 0;
}

int APS5_VABI sceHttpSetSendTimeOut(int id, uint32_t usec) {
    if (HttpHasObject_nid_no_patch(id)) NotImplemented_nid_no_patch(__func__);
    (void)id;
    (void)usec;
    return 0;
}

int APS5_VABI sceHttpsSetSslCallback(int id, HttpsCallback cbfunc, void* user_arg) {
    if (HttpHasObject_nid_no_patch(id) && cbfunc) NotImplemented_nid_no_patch(__func__);
    (void)id;
    (void)cbfunc;
    (void)user_arg;
    return 0;
}

int APS5_VABI sceHttpTerm_nid_postfix(int http_ctx_id) {
    std::vector<std::shared_ptr<HttpEpoll>> epolls;
    {
        std::lock_guard lock(g_stateMutex);
        if (g_contexts.empty()) return ERROR_BEFORE_INIT;
        if (g_contexts.erase(http_ctx_id) == 0) return ERROR_INVALID_ID;
        HttpContextStopped_nid_no_patch(http_ctx_id);
        for (auto it = g_epolls.begin(); it != g_epolls.end();) {
            if (it->second->Context() == http_ctx_id) {
                epolls.push_back(std::move(it->second));
                it = g_epolls.erase(it);
            } else ++it;
        }
    }
    for (const auto& epoll : epolls) MarkDestroyed(*epoll);
    return 0;
}

int APS5_VABI sceHttpUnsetEpoll(int id) {
    return HttpBindEpoll_nid_no_patch(id, nullptr, nullptr, nullptr);
}

int APS5_VABI sceHttpGetEpoll(int id, HttpEpollHandle* eh, void** user_arg) {
    return HttpGetEpoll_nid_no_patch(id, eh, user_arg);
}

int APS5_VABI sceHttpWaitRequest(HttpEpollHandle eh, HttpNBEvent* nbev, int maxevents, int timeout) {
    std::shared_ptr<HttpEpoll> epoll;
    {
        std::lock_guard lock(g_stateMutex);
        if (g_contexts.empty()) return ERROR_BEFORE_INIT;
        if (!eh || !nbev || maxevents <= 0) return ERROR_INVALID_VALUE;
        epoll = FindEpoll(eh);
        if (!epoll) return ERROR_INVALID_ID;
    }
    std::unique_lock lock(epoll->mutex);
    const auto woken = [&] {
        std::erase_if(epoll->events, [](const auto& entry) {
            auto alive = entry.alive.lock();
            return !alive || !alive->load();
        });
        return epoll->aborted || epoll->destroyed || epoll->exhausted || !epoll->events.empty();
    };
    if (timeout < 0) {
        while (!woken()) epoll->wake.Wait(lock);
    } else {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::microseconds(timeout);
        while (!woken() && std::chrono::steady_clock::now() < deadline) epoll->wake.WaitUntil(lock, deadline);
    }
    if (epoll->aborted) return ERROR_ABORTED;
    if (epoll->destroyed) return 0;
    if (epoll->exhausted) return ERROR_OUT_OF_MEMORY;
    int count = 0;
    while (count < maxevents && !epoll->events.empty()) {
        nbev[count++] = epoll->events.front().event;
        epoll->events.pop_front();
    }
    return count;
}

int APS5_VABI sceHttpRedirectCacheFlush(int http_ctx_id) {
    (void)http_ctx_id;
    return 0;
}

int APS5_VABI sceHttpSetRequestStatusCallback(int id, HttpRequestStatusCallback callback, void* argument) {
    if (!HttpHasObject_nid_no_patch(id)) return ERROR_INVALID_ID;
    std::lock_guard lock(g_statusMutex);
    if (callback) g_statusCallbacks[id] = {callback, argument};
    else g_statusCallbacks.erase(id);
    return 0;
}

int APS5_VABI sceHttpParseResponseHeader(const char* header, std::size_t headerLen, const char* fieldStr,
                                       const char** fieldValue, std::size_t* valueLen) {
    constexpr int invalidResponse = static_cast<int>(0x80432060);
    constexpr int invalidValue = static_cast<int>(0x804321FE);
    constexpr int notFound = static_cast<int>(0x80432025);
    if (!header) return invalidResponse;
    if (!fieldStr || !fieldValue || !valueLen) return invalidValue;

    std::size_t fieldLen = 0;
    while (fieldLen < 0xfff && fieldStr[fieldLen] != '\0') ++fieldLen;
    const std::string_view input(header, headerLen);
    const auto isSpace = [](char c) { return c == ' ' || (c >= '\t' && c <= '\r'); };
    const auto lower = [](char c) { return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c; };
    std::size_t start = 0;
    bool found = false;
    while (start < headerLen) {
        if (!isSpace(input[start]) && fieldLen < headerLen - start && input[start + fieldLen] == ':') {
            std::size_t i = 0;
            while (i < fieldLen && lower(input[start + i]) == lower(fieldStr[i])) ++i;
            if (i == fieldLen) {
                start += fieldLen + 1;
                found = true;
                break;
            }
        }
        const auto newline = input.find('\n', start);
        if (newline == std::string_view::npos) break;
        start = newline + 1;
    }
    if (!found) return notFound;

    while (start < headerLen && isSpace(input[start])) {
        if (input[start++] == '\n') break;
    }
    std::size_t end = headerLen;
    std::size_t consumed = headerLen;
    std::size_t scan = start;
    while (scan < headerLen) {
        const auto newline = input.find('\n', scan);
        if (newline == std::string_view::npos) break;
        const auto next = newline + 1;
        if (next < headerLen && (input[next] == ' ' || input[next] == '\t')) {
            scan = next;
            continue;
        }
        end = newline > start && input[newline - 1] == '\r' ? newline - 1 : newline;
        consumed = next;
        break;
    }
    if (end == start) {
        *fieldValue = nullptr;
        *valueLen = 0;
        return 0;
    }
    if (consumed > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::out_of_range("sceHttpParseResponseHeader: consumed byte count exceeds int");
    }
    *fieldValue = header + start;
    *valueLen = end - start;
    return static_cast<int>(consumed);
}

int APS5_VABI sceHttpSetCookieRecvCallback(int id, HttpCookieRecvCallback cbfunc, void* user_arg) {
    if (HttpHasObject_nid_no_patch(id) && (cbfunc != nullptr)) NotImplemented_nid_no_patch(__func__);
    (void)id;
    (void)cbfunc;
    (void)user_arg;
    return 0;
}

int APS5_VABI sceHttpSetRedirectCallback(int id, HttpRedirectCallback cbfunc, void* user_arg) {
    if (HttpHasObject_nid_no_patch(id) && (cbfunc != nullptr)) NotImplemented_nid_no_patch(__func__);
    (void)id;
    (void)cbfunc;
    (void)user_arg;
    return 0;
}

int APS5_VABI sceHttpAbortWaitRequest(HttpEpollHandle eh) {
    std::shared_ptr<HttpEpoll> epoll;
    {
        std::lock_guard lock(g_stateMutex);
        if (g_contexts.empty()) return ERROR_BEFORE_INIT;
        if (!eh) return ERROR_INVALID_VALUE;
        epoll = FindEpoll(eh);
        if (!epoll) return ERROR_INVALID_ID;
    }
    std::lock_guard lock(epoll->mutex);
    epoll->aborted = true;
    epoll->wake.NotifyAll();
    return 0;
}

int APS5_VABI sceHttpsGetCaList(int http_ctx_id, HttpsCaList* ca_list) {
    if (HttpHasCertificates_nid_no_patch(http_ctx_id)) NotImplemented_nid_no_patch(__func__);
    (void)http_ctx_id;
    if (!ca_list) return ERROR_INVALID_VALUE;
    ca_list->certs = nullptr;
    ca_list->certsNum = 0;
    return 0;
}

int APS5_VABI sceHttpsFreeCaList(int http_ctx_id, HttpsCaList* ca_list) {
    (void)http_ctx_id;
    if (!ca_list) return ERROR_INVALID_VALUE;
    ca_list->certs = nullptr;
    ca_list->certsNum = 0;
    return 0;
}
}
