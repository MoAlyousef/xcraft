#pragma once

#include "llvm_object_utils.hpp"
#include <cornerstone/cornerstone.hpp>
#include <set>
#include <utility>

struct CstnTarget {
    cstn::Arch arch;      // cornerstone's coarse ISA enum
    std::string cpu;      // canonical CPU / arch-name (LLVM style)
    std::string features; // comma-separated "+feature[,-feature]" string
};

namespace xcft {
CstnTarget make_cstn_target(const BinaryInfo& binary_info);
}
