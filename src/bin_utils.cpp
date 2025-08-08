#include "bin_utils.hpp"
#include <xcraft/enums.hpp>

namespace xcft {
CstnTarget make_cstn_target(const BinaryInfo& binary_info) {
    CstnTarget t{};

    switch (binary_info.arch) {
    case Architecture::X86:
        t.arch = cstn::Arch::x86;
        t.cpu  = "pentium";
        break;

    case Architecture::X86_64:
        t.arch = cstn::Arch::x86_64;
        t.cpu  = "x86-64";
        break;

    case Architecture::Arm:
        t.arch = cstn::Arch::arm;
        t.cpu  = (binary_info.endianness == LLVMEndianness::Big) ? "armeb" : "arm";
        // Note: THUMB mode detection would need additional binary analysis
        break;

    case Architecture::Aarch64:
        t.arch = cstn::Arch::aarch64;
        t.cpu  = (binary_info.endianness == LLVMEndianness::Big)
                     ? "aarch64_be"
                     : "aarch64";
        break;

    default:
        throw std::runtime_error("Unsupported architecture");
    }

    if (!t.features.empty() && t.features.back() == ',')
        t.features.pop_back();

    return t;
}
} // namespace xcft
