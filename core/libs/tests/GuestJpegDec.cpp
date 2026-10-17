#include "SceTypes.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#include "Decoder/Jpeg.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <vector>

static_assert(sizeof(JpegDecCreateParam) == 0xC);
static_assert(sizeof(JpegDecParseParam) == 0x10);
static_assert(offsetof(JpegDecParseParam, jpeg_mem_size) == 0x8 && offsetof(JpegDecParseParam, decode_mode) == 0xC && offsetof(JpegDecParseParam, down_scale) == 0xE);
static_assert(sizeof(JpegDecDecodeParam) == 0x30);
static_assert(offsetof(JpegDecDecodeParam, coefficient_mem_addr) == 0x10 && offsetof(JpegDecDecodeParam, jpeg_mem_size) == 0x18);
static_assert(offsetof(JpegDecDecodeParam, image_mem_size) == 0x1C && offsetof(JpegDecDecodeParam, coefficient_mem_size) == 0x20);
static_assert(offsetof(JpegDecDecodeParam, decode_mode) == 0x24 && offsetof(JpegDecDecodeParam, down_scale) == 0x26);
static_assert(offsetof(JpegDecDecodeParam, pixel_format) == 0x28 && offsetof(JpegDecDecodeParam, alpha_value) == 0x2A && offsetof(JpegDecDecodeParam, image_pitch) == 0x2C);
static_assert(sizeof(JpegDecImageInfo) == 0x24);
static_assert(offsetof(JpegDecImageInfo, color_space) == 0x8 && offsetof(JpegDecImageInfo, component_number) == 0xA);
static_assert(offsetof(JpegDecImageInfo, component_id) == 0xC && offsetof(JpegDecImageInfo, sampling_factor) == 0x10);
static_assert(offsetof(JpegDecImageInfo, coefficient_mem_size) == 0x14 && offsetof(JpegDecImageInfo, suitable_csc_attribute) == 0x18);
static_assert(offsetof(JpegDecImageInfo, output_image_width) == 0x1C && offsetof(JpegDecImageInfo, output_image_height) == 0x20);

extern "C" {
std::int32_t APS5_VABI sceJpegDecQueryMemorySize(const JpegDecCreateParam*);
std::int32_t APS5_VABI sceJpegDecCreate(const JpegDecCreateParam*, void*, std::uint32_t, void**);
std::int32_t APS5_VABI sceJpegDecDelete(void*);
std::int32_t APS5_VABI sceJpegDecParseHeader(const JpegDecParseParam*, JpegDecImageInfo*);
std::int32_t APS5_VABI sceJpegDecDecode(void*, const JpegDecDecodeParam*, JpegDecImageInfo*);
}

static void Require(bool value) { if (!value) std::abort(); }

template<typename TFunction>
static bool ThrowsRuntimeError(TFunction function) {
    try {
        function();
    } catch (const std::runtime_error&) {
        return true;
    }
    return false;
}

static std::vector<std::uint8_t> TestJpeg(std::uint32_t width, std::uint32_t height, std::uint32_t channels) {
    std::vector<std::uint8_t> pixels(static_cast<std::size_t>(width) * height * channels);
    for (std::size_t i = 0; i < pixels.size(); ++i) pixels[i] = static_cast<std::uint8_t>(10 + i * 13);
    return Decoder::Jpeg::Encode(pixels, width, height, channels, 90);
}

static JpegDecDecodeParam DecodeParam(const std::vector<std::uint8_t>& jpeg, std::vector<std::uint8_t>& image, std::uint32_t pitch) {
    JpegDecDecodeParam param{};
    param.jpeg_mem_addr = jpeg.data();
    param.image_mem_addr = image.data();
    param.coefficient_mem_addr = nullptr;
    param.jpeg_mem_size = static_cast<std::uint32_t>(jpeg.size());
    param.image_mem_size = static_cast<std::uint32_t>(image.size());
    param.coefficient_mem_size = 0;
    param.decode_mode = 0;
    param.down_scale = 1;
    param.pixel_format = 0;
    param.alpha_value = 0xFF;
    param.image_pitch = pitch;
    return param;
}

static void CheckDownscale(void* handle, std::uint32_t width, std::uint32_t height, std::uint32_t channels,
                           Decoder::Jpeg::Sampling sampling) {
    const std::uint8_t color[] = {40, 110, 180};
    std::vector<std::uint8_t> source(static_cast<std::size_t>(width) * height * channels);
    for (std::size_t pixel = 0; pixel < source.size() / channels; ++pixel)
        for (std::size_t channel = 0; channel < channels; ++channel) source[pixel * channels + channel] = color[channel];
    const auto jpeg = Decoder::Jpeg::Encode(source, width, height, channels, 100, sampling);
    for (std::uint16_t scale : {2, 4, 8}) {
        const std::uint32_t outputWidth = (width + scale - 1) / scale;
        const std::uint32_t outputHeight = (height + scale - 1) / scale;
        const std::uint32_t rowSize = outputWidth * 4;
        JpegDecImageInfo info{};
        const JpegDecParseParam parse{jpeg.data(), static_cast<std::uint32_t>(jpeg.size()), 0, scale};
        Require(sceJpegDecParseHeader(&parse, &info) == 0);
        Require(info.image_width == width && info.image_height == height && info.component_number == channels);
        Require(info.output_image_width == outputWidth && info.output_image_height == outputHeight);
        std::vector<std::uint8_t> incompleteOutput(outputWidth * outputHeight * 4 + 16, 0xcc);
        auto incomplete = DecodeParam(jpeg, incompleteOutput, 0);
        incomplete.down_scale = scale;
        incomplete.jpeg_mem_size -= 2;
        Require(sceJpegDecDecode(handle, &incomplete, nullptr) == static_cast<std::int32_t>(0x80690012));
        Require(std::all_of(incompleteOutput.begin(), incompleteOutput.end(), [](auto byte) { return byte == 0xcc; }));
        for (std::uint16_t format : {0, 1}) {
            for (std::uint32_t pitch : {0u, rowSize, rowSize + 7}) {
                const auto stride = pitch ? pitch : rowSize;
                const auto size = (outputHeight - 1) * stride + rowSize;
                std::vector<std::uint8_t> output(size + 16, 0xcc);
                auto param = DecodeParam(jpeg, output, pitch);
                param.image_mem_size = size;
                param.down_scale = scale;
                param.pixel_format = format;
                param.alpha_value = 0x77;
                Require(sceJpegDecDecode(handle, &param, &info) == static_cast<std::int32_t>(outputWidth << 16 | outputHeight));
                Require(info.image_width == width && info.image_height == height);
                Require(info.output_image_width == outputWidth && info.output_image_height == outputHeight);
                for (std::uint32_t y = 0; y < outputHeight; ++y) {
                    for (std::uint32_t x = 0; x < outputWidth; ++x) {
                        const auto* pixel = output.data() + y * stride + x * 4;
                        for (std::uint32_t channel = 0; channel < 3; ++channel) {
                            const auto expected = color[channels == 1 ? 0 : format == 1 ? 2 - channel : channel];
                            Require(std::abs(static_cast<int>(pixel[channel]) - expected) <= 3);
                        }
                        Require(pixel[3] == 0x77);
                    }
                    if (y + 1 < outputHeight)
                        for (std::uint32_t byte = rowSize; byte < stride; ++byte) Require(output[y * stride + byte] == 0xcc);
                }
                Require(std::all_of(output.begin() + size, output.end(), [](auto byte) { return byte == 0xcc; }));
                std::fill(output.begin(), output.end(), 0xcc);
                param.image_mem_size = size - 1;
                Require(sceJpegDecDecode(handle, &param, nullptr) == static_cast<std::int32_t>(0x80690002));
                Require(std::all_of(output.begin(), output.end(), [](auto byte) { return byte == 0xcc; }));
                param.image_mem_size = size;
                param.image_pitch = rowSize - 1;
                Require(sceJpegDecDecode(handle, &param, nullptr) == static_cast<std::int32_t>(0x80690003));
                Require(std::all_of(output.begin(), output.end(), [](auto byte) { return byte == 0xcc; }));
            }
        }
    }
}

int main() {
    constexpr std::int32_t invalidAddr = static_cast<std::int32_t>(0x80690001);
    constexpr std::int32_t invalidSize = static_cast<std::int32_t>(0x80690002);
    constexpr std::int32_t invalidParam = static_cast<std::int32_t>(0x80690003);
    constexpr std::int32_t invalidHandle = static_cast<std::int32_t>(0x80690004);
    constexpr std::int32_t invalidWorkMemory = static_cast<std::int32_t>(0x80690005);
    constexpr std::int32_t invalidData = static_cast<std::int32_t>(0x80690010);

    const std::vector<std::uint8_t> jpeg = TestJpeg(7, 5, 3);
    JpegDecImageInfo info{};
    const JpegDecParseParam parseParam{jpeg.data(), static_cast<std::uint32_t>(jpeg.size()), 0, 1};
    Require(sceJpegDecParseHeader(nullptr, &info) == invalidParam);
    Require(sceJpegDecParseHeader(&parseParam, nullptr) == invalidAddr);
    const JpegDecParseParam emptyParam{nullptr, 0, 0, 1};
    Require(sceJpegDecParseHeader(&emptyParam, &info) == invalidAddr);
    for (std::uint16_t scale : {0, 3, 16, UINT16_MAX}) {
        const JpegDecParseParam unsupportedScale{jpeg.data(), static_cast<std::uint32_t>(jpeg.size()), 0, scale};
        Require(ThrowsRuntimeError([&] { sceJpegDecParseHeader(&unsupportedScale, &info); }));
    }
    const std::vector<std::uint8_t> grayJpeg = TestJpeg(3, 2, 1);
    const JpegDecParseParam grayParse{grayJpeg.data(), static_cast<std::uint32_t>(grayJpeg.size()), 0, 1};
    Require(sceJpegDecParseHeader(&grayParse, &info) == 0);
    Require(info.image_width == 3 && info.image_height == 2 && info.component_number == 1);
    Require(sceJpegDecParseHeader(&parseParam, &info) == 0);
    Require(info.image_width == 7 && info.image_height == 5 && info.component_number == 3);
    Require(info.output_image_width == 7 && info.output_image_height == 5);
    Require(info.coefficient_mem_size == 0 && info.suitable_csc_attribute == 1);

    const JpegDecCreateParam param{sizeof(JpegDecCreateParam), info.suitable_csc_attribute, info.image_width};
    const std::int32_t memorySize = sceJpegDecQueryMemorySize(&param);
    Require(memorySize > 0);
    const JpegDecCreateParam fullParam{sizeof(JpegDecCreateParam), 2, info.image_width};
    Require(sceJpegDecQueryMemorySize(&fullParam) == memorySize);
    Require(sceJpegDecQueryMemorySize(nullptr) == invalidParam);
    const JpegDecCreateParam badSize{sizeof(JpegDecCreateParam) - 4, 1, 7};
    Require(sceJpegDecQueryMemorySize(&badSize) == invalidSize);
    for (const std::uint32_t attribute : {0u, 3u}) {
        const JpegDecCreateParam badAttribute{sizeof(JpegDecCreateParam), attribute, 7};
        Require(sceJpegDecQueryMemorySize(&badAttribute) == invalidParam);
    }

    std::vector<std::uint8_t> memory(static_cast<std::size_t>(memorySize) + 8);
    void* handle = nullptr;
    Require(sceJpegDecCreate(&param, memory.data(), 0, &handle) == invalidWorkMemory);
    Require(sceJpegDecCreate(&param, memory.data(), static_cast<std::uint32_t>(memorySize), nullptr) == invalidAddr);
    Require(sceJpegDecCreate(&fullParam, memory.data(), static_cast<std::uint32_t>(memorySize), &handle) == 0);
    Require(handle != nullptr);
    Require(sceJpegDecDelete(nullptr) == invalidHandle);
    Require(sceJpegDecDelete(handle) == 0);

    Require(sceJpegDecCreate(&param, memory.data(), static_cast<std::uint32_t>(memorySize), &handle) == 0);

    const std::optional<Decoder::Jpeg::Image> reference = Decoder::Jpeg::Decode(jpeg);
    Require(reference && reference->width == 7 && reference->height == 5 && reference->channels == 3);

    std::vector<std::uint8_t> image(7 * 5 * 4, 0xCC);
    JpegDecDecodeParam decodeParam = DecodeParam(jpeg, image, 7 * 4);
    Require(sceJpegDecDecode(nullptr, &decodeParam, &info) == invalidHandle);
    Require(sceJpegDecDecode(handle, nullptr, &info) == invalidParam);
    JpegDecDecodeParam badFormat = decodeParam;
    badFormat.pixel_format = 2;
    Require(sceJpegDecDecode(handle, &badFormat, &info) == invalidParam);
    for (std::uint16_t scale : {0, 3, 16, UINT16_MAX}) {
        JpegDecDecodeParam unsupportedScale = decodeParam;
        unsupportedScale.down_scale = scale;
        Require(ThrowsRuntimeError([&] { sceJpegDecDecode(handle, &unsupportedScale, &info); }));
    }
    JpegDecDecodeParam otherMode = decodeParam;
    otherMode.decode_mode = 1;
    Require(ThrowsRuntimeError([&] { sceJpegDecDecode(handle, &otherMode, &info); }));
    info = {};
    Require(sceJpegDecDecode(handle, &decodeParam, &info) == static_cast<std::int32_t>(7 << 16 | 5));
    Require(info.image_width == 7 && info.image_height == 5);
    Require(info.output_image_width == 7 && info.output_image_height == 5);
    for (std::size_t pixel = 0; pixel < 7 * 5; ++pixel) {
        for (std::size_t c = 0; c < 3; ++c) Require(image[pixel * 4 + c] == reference->pixels[pixel * 3 + c]);
        Require(image[pixel * 4 + 3] == 0xFF);
    }

    constexpr std::uint32_t pitch = 7 * 4 + 8;
    std::vector<std::uint8_t> bgra(4 * pitch + 7 * 4, 0xEE);
    JpegDecDecodeParam bgraParam = DecodeParam(jpeg, bgra, pitch);
    bgraParam.pixel_format = 1;
    bgraParam.alpha_value = 0x77;
    Require(sceJpegDecDecode(handle, &bgraParam, nullptr) == static_cast<std::int32_t>(7 << 16 | 5));
    for (std::size_t y = 0; y < 5; ++y) {
        for (std::size_t x = 0; x < 7; ++x) {
            const std::uint8_t* pixel = &bgra[y * pitch + x * 4];
            const std::uint8_t* rgba = &image[(y * 7 + x) * 4];
            Require(pixel[0] == rgba[2] && pixel[1] == rgba[1] && pixel[2] == rgba[0] && pixel[3] == 0x77);
        }
    }
    for (std::size_t y = 0; y < 4; ++y) {
        for (std::size_t x = 7 * 4; x < pitch; ++x) Require(bgra[y * pitch + x] == 0xEE);
    }

    const std::vector<std::uint8_t> garbage{0x00, 0x01, 0x02, 0x03};
    const JpegDecParseParam garbageParam{garbage.data(), static_cast<std::uint32_t>(garbage.size()), 0, 1};
    Require(sceJpegDecParseHeader(&garbageParam, &info) == invalidData);
    std::vector<std::uint8_t> garbageOut(64, 0);
    const JpegDecDecodeParam garbageDecode = DecodeParam(garbage, garbageOut, 4 * 4);
    Require(sceJpegDecDecode(handle, &garbageDecode, &info) == invalidData);

    for (const auto sampling : {Decoder::Jpeg::Sampling::Yuv444, Decoder::Jpeg::Sampling::Yuv422, Decoder::Jpeg::Sampling::Yuv420}) {
        for (std::uint32_t channels : {1u, 3u}) {
            CheckDownscale(handle, 17, 9, channels, sampling);
            CheckDownscale(handle, 16, 8, channels, sampling);
            CheckDownscale(handle, 1, 1, channels, sampling);
        }
    }
    Require(sceJpegDecDelete(handle) == 0);
    return 0;
}
