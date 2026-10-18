#pragma once

#include <cstddef>
#include <cstdint>

namespace SceSsl {

struct Data {
    std::uint8_t* ptr;
    std::size_t size;
};

struct CaCerts {
    Data* certs;
    std::size_t num;
    void* pool;
};

struct CaList {
    void** certs;
    int num;
};

struct MemoryPoolStats {
    std::size_t poolSize, maxInuseSize, currentInuseSize;
    std::uint32_t reserved;
};

static_assert(sizeof(Data) == 0x10);
static_assert(sizeof(CaCerts) == 0x18);
static_assert(sizeof(CaList) == 0x10);
static_assert(sizeof(MemoryPoolStats) == 0x20);

}

extern "C" int SslImportCaList_nid_no_patch(int context, const SceSsl::Data* input, SceSsl::CaList* output);
extern "C" void SslReleaseCaList_nid_no_patch(int context, SceSsl::CaList list);
extern "C" bool SslContextExists_nid_no_patch(int context);
