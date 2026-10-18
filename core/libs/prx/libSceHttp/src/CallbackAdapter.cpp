#include <curl/curl.h>

extern "C" CURLcode HttpReceiveCookie_nid_no_patch(void* data, void* cookies, const char* line,
    const char* domain, const char* path, int flags);

extern "C" CURLcode __wrap_Curl_cookie_add(void* data, void* cookies, const char* line,
    const char* domain, const char* path, int flags) {
    return HttpReceiveCookie_nid_no_patch(data, cookies, line, domain, path, flags);
}
