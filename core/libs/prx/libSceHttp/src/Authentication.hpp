#ifndef CORE_LIBS_PRX_LIBSCEHTTP_SRC_AUTHENTICATION_HPP
#define CORE_LIBS_PRX_LIBSCEHTTP_SRC_AUTHENTICATION_HPP

#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

struct HttpAuthChallenge {
    int type;
    std::map<std::string, std::string> parameters;
};

std::vector<HttpAuthChallenge> HttpParseChallenges_nid_no_patch(std::string_view text);
std::string HttpAuthQuality_nid_no_patch(const HttpAuthChallenge& challenge);
int HttpBuildAuthorization_nid_no_patch(const HttpAuthChallenge& challenge, std::string_view method,
    std::string_view target, std::string_view username, std::string_view password,
    std::span<const char> body, std::uint32_t count, std::string& authorization);

#endif
