#include "bin_utils.hpp"

namespace ctf {
std::pair<cs_arch, cs_mode> get_capstone_arch(
    LIEF::ARCHITECTURES larch, const std::set<LIEF::MODES> &lmodes
) {
    cs_arch arch = CS_ARCH_X86;
    cs_mode mode = CS_MODE_LITTLE_ENDIAN;
    switch (larch) {
    case LIEF::ARCHITECTURES::ARCH_ARM:
        arch = CS_ARCH_ARM;
        break;
    case LIEF::ARCHITECTURES::ARCH_ARM64:
        arch = CS_ARCH_AARCH64;
        break;
    case LIEF::ARCHITECTURES::ARCH_X86:
        arch = CS_ARCH_X86;
        break;
    default:
        throw std::runtime_error("Unsupported architecture");
    }
    for (const auto &m : lmodes) {
        switch (m) {
        case LIEF::MODES::MODE_32:
            mode = CS_MODE_32;
            break;
        case LIEF::MODES::MODE_64:
            mode = CS_MODE_64;
            break;
        default:
            continue;
        }
    }
    return std::make_pair(arch, mode);
}
} // namespace ctf
