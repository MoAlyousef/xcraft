#pragma once

namespace ctf {

enum class Architecture {
    X86_64,
    X86,
    Aarch64,
    Arm,
    Other,
};

enum class Os { Linux, Darwin, Windows, Unix, Other };

enum class RelroType { NoRelro, PartialRelro, FullRelro };
} // namespace ctf