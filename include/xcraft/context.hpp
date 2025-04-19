#pragma once

#include "enums.hpp"

namespace xcft {
struct Context {
    Architecture arch    = Architecture::X86_64;
    Endian endian        = Endian::Little;
    Os os                = Os::Linux;
    const char *terminal = "x-terminal-emulator -e";
    Context() noexcept;
};

extern Context CONTEXT;
} // namespace xcft
