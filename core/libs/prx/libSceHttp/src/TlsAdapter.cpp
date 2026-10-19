#include <mbedtls/ssl.h>

extern "C" int HttpSetPeerHostname_nid_no_patch(mbedtls_ssl_context* context, const char* hostname);

extern "C" int __wrap_mbedtls_ssl_set_hostname(mbedtls_ssl_context* context, const char* hostname) {
    return HttpSetPeerHostname_nid_no_patch(context, hostname);
}
