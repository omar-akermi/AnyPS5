#include "Decoder/Jpeg.hpp"

#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <utility>
#include <vector>

static void Require(bool value) { if (!value) std::abort(); }

template<typename TFunction>
static bool ThrowsInvalidArgument(TFunction function) {
    try {
        function();
    } catch (const std::invalid_argument&) {
        return true;
    }
    return false;
}

static bool IsJpeg(const std::vector<std::uint8_t>& data) {
    return data.size() > 4 && data[0] == 0xFF && data[1] == 0xD8 && data[data.size() - 2] == 0xFF && data.back() == 0xD9;
}

static int Difference(std::uint8_t left, std::uint8_t right) {
    return left > right ? left - right : right - left;
}

struct FrameInfo { int components; std::uint8_t sampling; };

static FrameInfo ReadFrame(const std::vector<std::uint8_t>& jpeg) {
    std::size_t offset = 2;
    while (offset + 3 < jpeg.size()) {
        Require(jpeg[offset++] == 0xFF);
        while (offset < jpeg.size() && jpeg[offset] == 0xFF) ++offset;
        Require(offset < jpeg.size());
        const std::uint8_t marker = jpeg[offset++];
        if (marker == 0xDA || marker == 0xD9) break;
        Require(offset + 1 < jpeg.size());
        const std::size_t length = (static_cast<std::size_t>(jpeg[offset]) << 8) | jpeg[offset + 1];
        Require(length >= 2 && offset + length <= jpeg.size());
        if (marker >= 0xC0 && marker <= 0xC3) return {jpeg[offset + 7], jpeg[offset + 9]};
        offset += length;
    }
    std::abort();
}

int main() {
    constexpr std::uint32_t width = 32;
    constexpr std::uint32_t height = 24;

    std::vector<std::uint8_t> rgb(width * height * 3);
    for (std::uint32_t y = 0; y < height; ++y) {
        for (std::uint32_t x = 0; x < width; ++x) {
            std::uint8_t* pixel = &rgb[(y * width + x) * 3];
            pixel[0] = static_cast<std::uint8_t>(x * 8);
            pixel[1] = static_cast<std::uint8_t>(y * 10);
            pixel[2] = 128;
        }
    }

    const std::vector<std::uint8_t> rgbJpeg = Decoder::Jpeg::Encode(rgb, width, height, 3, 90);
    Require(IsJpeg(rgbJpeg));
    Require(ReadFrame(rgbJpeg).components == 3 && ReadFrame(rgbJpeg).sampling == 0x11);
    const auto rgbImage = Decoder::Jpeg::Decode(rgbJpeg);
    Require(rgbImage.has_value());
    Require(rgbImage->width == width && rgbImage->height == height && rgbImage->channels == 3);
    Require(rgbImage->pixels.size() == rgb.size());
    long totalError = 0;
    for (std::size_t i = 0; i < rgb.size(); ++i) totalError += Difference(rgb[i], rgbImage->pixels[i]);
    Require(totalError / static_cast<long>(rgb.size()) < 4);

    std::vector<std::uint8_t> gray(width * height);
    for (std::uint32_t y = 0; y < height; ++y) {
        for (std::uint32_t x = 0; x < width; ++x) gray[y * width + x] = static_cast<std::uint8_t>((x + y) * 4);
    }
    const std::vector<std::uint8_t> grayJpeg = Decoder::Jpeg::Encode(gray, width, height, 1, 90);
    Require(IsJpeg(grayJpeg));
    Require(ReadFrame(grayJpeg).components == 1);
    const auto grayImage = Decoder::Jpeg::Decode(grayJpeg);
    Require(grayImage.has_value());
    Require(grayImage->width == width && grayImage->height == height);
    totalError = 0;
    for (std::size_t i = 0; i < gray.size(); ++i) totalError += Difference(gray[i], grayImage->pixels[i * grayImage->channels]);
    Require(totalError / static_cast<long>(gray.size()) < 4);

    Require(ThrowsInvalidArgument([&] { Decoder::Jpeg::Encode(rgb, width, height, 4, 90); }));
    Require(ThrowsInvalidArgument([&] { Decoder::Jpeg::Encode(rgb, width, height, 3, 0); }));
    Require(ThrowsInvalidArgument([&] { Decoder::Jpeg::Encode(rgb, width, height, 3, 101); }));
    Require(ThrowsInvalidArgument([&] { Decoder::Jpeg::Encode(rgb, 0, height, 3, 90); }));
    Require(ThrowsInvalidArgument([&] { Decoder::Jpeg::Encode(rgb, 0x10000, 1, 3, 90); }));
    Require(ThrowsInvalidArgument([&] { Decoder::Jpeg::Encode(rgb, width, height + 1, 3, 90); }));

    for (const auto [sampling, factor] : {std::pair{Decoder::Jpeg::Sampling::Yuv444, std::uint8_t{0x11}},
                                          std::pair{Decoder::Jpeg::Sampling::Yuv422, std::uint8_t{0x21}},
                                          std::pair{Decoder::Jpeg::Sampling::Yuv420, std::uint8_t{0x22}}}) {
        const auto encoded = Decoder::Jpeg::Encode(rgb, 31, 23, 3, 1, sampling);
        Require(ReadFrame(encoded).components == 3 && ReadFrame(encoded).sampling == factor);
        const auto highQuality = Decoder::Jpeg::Encode(rgb, 31, 23, 3, 100, sampling);
        Require(ReadFrame(highQuality).components == 3 && ReadFrame(highQuality).sampling == factor);
    }
    Require(ThrowsInvalidArgument([&] { Decoder::Jpeg::Encode(rgb, width, height, 3, 90, static_cast<Decoder::Jpeg::Sampling>(3)); }));
    Require(ThrowsInvalidArgument([&] { Decoder::Jpeg::Encode(rgb, width, height, 3, 90, Decoder::Jpeg::Sampling::Yuv444, 1, 1); }));
    Require(ThrowsInvalidArgument([&] { Decoder::Jpeg::Encode(rgb, width, height, 3, 90, Decoder::Jpeg::Sampling::Yuv444, 0x10000, 0); }));
    Require(ThrowsInvalidArgument([&] { Decoder::Jpeg::Encode(rgb, width, height, 3, 90, Decoder::Jpeg::Sampling::Yuv444, 0, 0x10000); }));

    for (std::uint32_t scale : {2u, 4u, 8u}) {
        const auto scaled = Decoder::Jpeg::Decode(rgbJpeg, scale);
        Require(scaled && scaled->width == (width + scale - 1) / scale && scaled->height == (height + scale - 1) / scale);
        Require(scaled->channels == 3 && scaled->pixels.size() == scaled->width * scaled->height * 3);
        const auto scaledGray = Decoder::Jpeg::Decode(grayJpeg, scale);
        Require(scaledGray && scaledGray->channels == 1 && scaledGray->width == (width + scale - 1) / scale);
        Require(scaledGray->height == (height + scale - 1) / scale);
        Require(scaledGray->pixels.size() == scaledGray->width * scaledGray->height);
        Require(!Decoder::Jpeg::Decode({}, scale));
        for (const auto size : {std::size_t{2}, rgbJpeg.size() / 2, rgbJpeg.size() - 2})
            Require(!Decoder::Jpeg::Decode(std::span<const std::uint8_t>(rgbJpeg.data(), size), scale));
    }
    for (std::uint32_t scale : {0u, 3u, 16u, UINT32_MAX})
        Require(ThrowsInvalidArgument([&] { Decoder::Jpeg::Decode(rgbJpeg, scale); }));
    const auto unscaled = Decoder::Jpeg::Decode(rgbJpeg, 1);
    Require(unscaled && unscaled->pixels == rgbImage->pixels);
    std::vector<std::uint8_t> checker(8 * 8);
    for (std::uint32_t y = 0; y < 8; ++y)
        for (std::uint32_t x = 0; x < 8; ++x) checker[y * 8 + x] = (x + y) % 2 ? 255 : 0;
    const auto checkerJpeg = Decoder::Jpeg::Encode(checker, 8, 8, 1, 100);
    const auto average = Decoder::Jpeg::Decode(checkerJpeg, 8);
    Require(average && average->width == 1 && average->height == 1 && average->channels == 1);
    Require(Difference(average->pixels[0], 128) <= 1);

    Require(!Decoder::Jpeg::Decode({}).has_value());
    const std::vector<std::uint8_t> garbage{1, 2, 3, 4, 5, 6, 7, 8};
    Require(!Decoder::Jpeg::Decode(garbage).has_value());

    return 0;
}
