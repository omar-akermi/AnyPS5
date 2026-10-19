#include "Authentication.hpp"
#include "HttpErrors.hpp"
#include <mbedtls/base64.h>
#include <mbedtls/md.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform_util.h>
#include <algorithm>
#include <array>
#include <cstdio>

namespace {

std::string Lower(std::string_view text) {
    std::string result(text);
    for (char& value : result)
        if (value >= 'A' && value <= 'Z') value += 'a' - 'A';
    return result;
}

bool Token(char value) {
    const unsigned char c = value;
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        std::string_view("!#$%&'*+-.^_`|~").find(value) != std::string_view::npos;
}

void Blanks(std::string_view text, std::size_t& position) {
    while (position < text.size() && (text[position] == ' ' || text[position] == '\t')) ++position;
}

std::string ReadToken(std::string_view text, std::size_t& position) {
    const auto start = position;
    while (position < text.size() && Token(text[position])) ++position;
    return std::string(text.substr(start, position - start));
}

std::string Parameter(const HttpAuthChallenge& challenge, const char* name) {
    const auto found = challenge.parameters.find(name);
    return found == challenge.parameters.end() ? std::string() : found->second;
}

std::string Hex(std::span<const unsigned char> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result(bytes.size() * 2, '0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        result[index * 2] = digits[bytes[index] >> 4];
        result[index * 2 + 1] = digits[bytes[index] & 15];
    }
    return result;
}

std::string Hash(mbedtls_md_type_t algorithm, std::string text) {
    const auto* info = mbedtls_md_info_from_type(algorithm);
    std::array<unsigned char, MBEDTLS_MD_MAX_SIZE> digest{};
    const int result = info ? mbedtls_md(info, reinterpret_cast<const unsigned char*>(text.data()), text.size(), digest.data()) : -1;
    mbedtls_platform_zeroize(text.data(), text.size());
    return result ? std::string() : Hex(std::span(digest.data(), mbedtls_md_get_size(info)));
}

std::string Nonce() {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context random;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&random);
    std::array<unsigned char, 16> bytes{};
    int result = mbedtls_ctr_drbg_seed(&random, mbedtls_entropy_func, &entropy, nullptr, 0);
    if (!result) result = mbedtls_ctr_drbg_random(&random, bytes.data(), bytes.size());
    mbedtls_ctr_drbg_free(&random);
    mbedtls_entropy_free(&entropy);
    return result ? std::string() : Hex(bytes);
}

std::string Quote(std::string_view text) {
    std::string result = "\"";
    for (char value : text) {
        if (value == '\\' || value == '"') result += '\\';
        result += value;
    }
    return result + '"';
}

}

std::vector<HttpAuthChallenge> HttpParseChallenges_nid_no_patch(std::string_view text) {
    std::vector<HttpAuthChallenge> result;
    std::size_t position = 0;
    while (position < text.size()) {
        Blanks(text, position);
        if (position == text.size()) break;
        if (text[position] == ',') { ++position; continue; }
        const auto scheme = Lower(ReadToken(text, position));
        if (scheme.empty()) return {};
        HttpAuthChallenge challenge{scheme == "basic" ? 0 : scheme == "digest" ? 1 : -1, {}};
        if (challenge.type < 0) {
            bool quoted = false;
            while (position < text.size()) {
                const char value = text[position++];
                if (value == '\\' && quoted && position < text.size()) ++position;
                else if (value == '"') quoted = !quoted;
                else if (value == ',' && !quoted) break;
            }
            continue;
        }
        for (;;) {
            Blanks(text, position);
            if (position == text.size()) break;
            if (text[position] == ',') { ++position; Blanks(text, position); }
            const auto start = position;
            const auto key = Lower(ReadToken(text, position));
            Blanks(text, position);
            if (position == text.size() || text[position] != '=') { position = start; break; }
            ++position;
            Blanks(text, position);
            std::string value;
            if (position < text.size() && text[position] == '"') {
                ++position;
                bool closed = false;
                while (position < text.size()) {
                    char c = text[position++];
                    if (c == '"') { closed = true; break; }
                    if (c == '\\') {
                        if (position == text.size()) return {};
                        c = text[position++];
                    }
                    if ((static_cast<unsigned char>(c) < 32 && c != '\t') || c == 127) return {};
                    value += c;
                }
                if (!closed) return {};
            } else value = ReadToken(text, position);
            if (key.empty() || !challenge.parameters.emplace(key, std::move(value)).second) return {};
            Blanks(text, position);
            if (position < text.size() && text[position] != ',') return {};
        }
        if (challenge.type >= 0) result.push_back(std::move(challenge));
    }
    return result;
}

std::string HttpAuthQuality_nid_no_patch(const HttpAuthChallenge& challenge) {
    auto values = Parameter(challenge, "qop");
    if (values.empty()) return {};
    std::size_t position = 0;
    bool integrity = false;
    while (position < values.size()) {
        Blanks(values, position);
        const auto token = Lower(ReadToken(values, position));
        if (token == "auth") return "auth";
        if (token == "auth-int") integrity = true;
        Blanks(values, position);
        if (position == values.size()) break;
        if (values[position++] != ',') return "unsupported";
    }
    return integrity ? "auth-int" : "unsupported";
}

int HttpBuildAuthorization_nid_no_patch(const HttpAuthChallenge& challenge, std::string_view method,
    std::string_view target, std::string_view username, std::string_view password,
    std::span<const char> body, std::uint32_t count, std::string& authorization) {
    const auto invalid = [](std::string_view value) {
        return std::any_of(value.begin(), value.end(), [](unsigned char c) { return c < 32 || c == 127; });
    };
    if (invalid(username) || invalid(password)) return ERROR_INVALID_VALUE;
    if (challenge.type == 0) {
        if (username.find(':') != std::string_view::npos) return ERROR_INVALID_VALUE;
        std::string plain = std::string(username) + ':' + std::string(password);
        std::vector<unsigned char> output((plain.size() + 2) / 3 * 4 + 1);
        std::size_t size = 0;
        const int result = mbedtls_base64_encode(output.data(), output.size(), &size,
            reinterpret_cast<const unsigned char*>(plain.data()), plain.size());
        mbedtls_platform_zeroize(plain.data(), plain.size());
        if (result) return ERROR_NETWORK;
        authorization = "Basic " + std::string(reinterpret_cast<char*>(output.data()), size);
        return 0;
    }
    const auto realm = Parameter(challenge, "realm");
    const auto nonce = Parameter(challenge, "nonce");
    const auto requestedAlgorithm = Parameter(challenge, "algorithm");
    auto algorithm = Lower(requestedAlgorithm.empty() ? "MD5" : requestedAlgorithm);
    const bool session = algorithm.ends_with("-sess");
    if (session) algorithm.resize(algorithm.size() - 5);
    const auto hash = algorithm == "md5" ? MBEDTLS_MD_MD5 : algorithm == "sha-256" ? MBEDTLS_MD_SHA256 : MBEDTLS_MD_NONE;
    const auto quality = HttpAuthQuality_nid_no_patch(challenge);
    if (challenge.type != 1 || nonce.empty() || hash == MBEDTLS_MD_NONE || quality == "unsupported")
        return static_cast<int>(0x80431069);
    const auto clientNonce = Nonce();
    if (clientNonce.empty()) return ERROR_NETWORK;
    auto a1 = Hash(hash, std::string(username) + ':' + realm + ':' + std::string(password));
    if (a1.empty()) return ERROR_NETWORK;
    if (session) a1 = Hash(hash, a1 + ':' + nonce + ':' + clientNonce);
    std::string a2 = std::string(method) + ':' + std::string(target);
    if (quality == "auth-int") {
        const auto entity = Hash(hash, std::string(body.begin(), body.end()));
        if (entity.empty()) return ERROR_NETWORK;
        a2 += ':' + entity;
    }
    a2 = Hash(hash, std::move(a2));
    char counter[9];
    std::snprintf(counter, sizeof(counter), "%08x", count);
    const auto response = Hash(hash, a1 + ':' + nonce + ':' +
        (quality.empty() ? std::string() : std::string(counter) + ':' + clientNonce + ':' + quality + ':') + a2);
    if (a1.empty() || a2.empty() || response.empty()) return ERROR_NETWORK;
    const bool userHash = Lower(Parameter(challenge, "userhash")) == "true";
    const auto user = userHash ? Hash(hash, std::string(username) + ':' + realm) : std::string(username);
    authorization = "Digest username=" + Quote(user) + ", realm=" + Quote(realm) + ", nonce=" + Quote(nonce) +
        ", uri=" + Quote(target) + ", response=" + Quote(response) + ", algorithm=" +
        (requestedAlgorithm.empty() ? "MD5" : requestedAlgorithm);
    if (const auto opaque = Parameter(challenge, "opaque"); !opaque.empty()) authorization += ", opaque=" + Quote(opaque);
    if (!quality.empty()) authorization += ", qop=" + quality + ", nc=" + counter + ", cnonce=" + Quote(clientNonce);
    else if (session) authorization += ", cnonce=" + Quote(clientNonce);
    if (userHash) authorization += ", userhash=true";
    return 0;
}
