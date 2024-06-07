#include "ctf/enums.hpp"
#include <bit>
#include <ctf/context.hpp>

namespace ctf {
Context::Context() noexcept {
// NOLINTBEGIN
#ifdef _WIN32
    os       = Os::Windows;
    terminal = "start cmd.exe /k";
#elif defined(__APPLE__)
    os       = Os::Darwin;
    terminal = " open -b com.apple.terminal";
#elif defined(__linux__)
    os = Os::Linux;
#else
    os       = Os::Unix;
    terminal = "xterm -e";
#endif

#if defined(_M_IX86) || defined(__i386__)
    arch = Architecture::X86;
#elif defined(__x86_64__) || defined(_M_X64)
    arch = Architecture::X86_64;
#elif defined(__aarch64__) || defined(_M_ARM64)
    arch = Architecture::Aarch64;
#else
    arch = Architecture::Arm;
#endif
    // NOLINTEND
    if (std::endian::native == std::endian::little)
        endian = Endian::Little;
    else
        endian = Endian::Big;
}

Context CONTEXT;
} // namespace ctf
