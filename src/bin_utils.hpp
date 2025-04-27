#pragma once

#include <LIEF/LIEF.hpp>
#include <cornerstone/cornerstone.hpp>
#include <set>
#include <utility>

namespace xcft {
cstn::Arch get_cstn_arch(
    LIEF::ARCHITECTURES larch, const std::set<LIEF::MODES> &lmodes
);
}
