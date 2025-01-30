#pragma once
#include <cstdint>

namespace ctf {

enum class Bits: std::int8_t {
    Bits32 = 32,
    Bits64 = 64,
};

enum class Endian: std::int8_t {
    Little,
    Big,
};

enum class Architecture: std::int8_t {
    X86_64,
    X86,
    Aarch64,
    Arm,
    Other,
};

enum class Os: std::int8_t { Linux, Darwin, Windows, Unix, Other };

enum class RelroType: std::int8_t { NoRelro, PartialRelro, FullRelro };
} // namespace ctf