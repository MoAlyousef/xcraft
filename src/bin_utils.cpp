#include "bin_utils.hpp"

namespace xcft {
CstnTarget make_cstn_target(
    LIEF::ARCHITECTURES a, const std::set<LIEF::MODES> &m, LIEF::ENDIANNESS e
) {
    using LIEF::ENDIANNESS;
    using LIEF::MODES;

    CstnTarget t{};

    switch (a) {
    case LIEF::ARCHITECTURES::ARCH_X86:
        if (m.count(MODES::MODE_64)) {
            t.arch = cstn::Arch::x86_64;
            t.cpu  = "x86-64";
        } else {
            t.arch = cstn::Arch::x86;
            t.cpu  = "pentium";
        }
        break;

    case LIEF::ARCHITECTURES::ARCH_ARM:
        t.arch = cstn::Arch::arm;
        t.cpu  = (e == ENDIANNESS::ENDIAN_BIG) ? "armeb" : "arm";
        if (m.count(MODES::MODE_THUMB))
            t.features += "+thumb-mode,+thumb2,";
        break;

    case LIEF::ARCHITECTURES::ARCH_ARM64:
        t.arch = cstn::Arch::aarch64;
        t.cpu  = (e == ENDIANNESS::ENDIAN_BIG)
                     ? "aarch64_be"
                     : "aarch64";
        break;

    case LIEF::ARCHITECTURES::ARCH_RISCV:
        if (m.count(MODES::MODE_64)) {
            t.arch = cstn::Arch::riscv64;
            t.cpu  = (e == ENDIANNESS::ENDIAN_BIG) ? "riscv64be" : "riscv64";
        } else {
            t.arch = cstn::Arch::riscv32;
            t.cpu  = (e == ENDIANNESS::ENDIAN_BIG) ? "riscv32be" : "riscv32";
        }
        break;

    default:
        throw std::runtime_error("Unsupported architecture in LIEF header");
    }

    if (!t.features.empty() && t.features.back() == ',')
        t.features.pop_back();

    return t;
}
} // namespace xcft
