#ifndef CORE_LIBS_PRX_LIBSCEHTTP_SRC_TRANSPORT_HPP
#define CORE_LIBS_PRX_LIBSCEHTTP_SRC_TRANSPORT_HPP

#include "SceTypes.hpp"
#include <atomic>
#include <memory>

class HttpEventSink {
public:
    explicit HttpEventSink(int contextId) : context(contextId) {}
    virtual ~HttpEventSink() = default;
    int Context() const { return context; }
    virtual void Notify(HttpNBEvent event, std::weak_ptr<std::atomic<bool>> alive) noexcept = 0;

private:
    int context;
};

int HttpBindEpoll_nid_no_patch(int id, std::shared_ptr<HttpEventSink> sink, HttpEpollHandle handle, void* argument);
int HttpGetEpoll_nid_no_patch(int id, HttpEpollHandle* handle, void** argument);

int HttpNextHandle_nid_no_patch();
void HttpContextStarted_nid_no_patch(int id);
void HttpContextStopped_nid_no_patch(int id);
void HttpForgetCallback_nid_no_patch(int id);
bool HttpHasCallback_nid_no_patch(int id);
bool HttpHasObject_nid_no_patch(int id);
bool HttpHasCertificates_nid_no_patch(int id);

#endif
