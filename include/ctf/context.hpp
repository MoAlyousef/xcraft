#pragma once

#include "enums.hpp"
#include <bit>

namespace ctf {
struct Context {
    Architecture arch    = Architecture::X86_64;
    std::endian endian   = std::endian::little;
    Os os                = Os::Linux;
    const char *terminal = "x-terminal-emulator -e";
    Context() noexcept;
};

extern Context CONTEXT;
} // namespace ctf
