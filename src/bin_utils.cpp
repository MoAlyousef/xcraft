#include "bin_utils.hpp"

namespace xcft {
cstn::Arch get_cstn_arch(
    LIEF::ARCHITECTURES larch, const std::set<LIEF::MODES> &lmodes
) {
    using namespace cstn;
    Arch arch = Arch::x86;
    switch (larch) {
    case LIEF::ARCHITECTURES::ARCH_ARM:
        arch = Arch::arm;
        break;
    case LIEF::ARCHITECTURES::ARCH_ARM64:
        arch = Arch::aarch64;
        break;
    case LIEF::ARCHITECTURES::ARCH_X86:
        for (const auto &m : lmodes) {
            switch (m) {
            case LIEF::MODES::MODE_32:
                arch = Arch::x86;
                break;
            case LIEF::MODES::MODE_64:
                arch = Arch::x86_64;
                break;
            default:
                continue;
            }
        }
        break;
    default:
        throw std::runtime_error("Unsupported architecture");
    }
    return arch;
}
} // namespace xcft
