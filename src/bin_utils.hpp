#pragma once

#include <LIEF/LIEF.hpp>
#include <capstone/capstone.h>
#include <set>
#include <utility>

namespace ctf {
std::pair<cs_arch, cs_mode> get_capstone_arch(
    LIEF::ARCHITECTURES larch, const std::set<LIEF::MODES> &lmodes
);
}
