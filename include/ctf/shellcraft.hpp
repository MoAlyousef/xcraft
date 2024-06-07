#pragma once

#include <ctf/enums.hpp>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ctf {

std::string disassemble(
    std::span<unsigned char> code,
    Architecture arch,
    std::optional<size_t> address = std::nullopt
);

std::string disassemble(
    std::span<unsigned char> code, std::optional<size_t> address = std::nullopt
);

std::vector<unsigned char> assemble(const char *code, Architecture arch);

std::vector<unsigned char> assemble(const char *code);

std::vector<unsigned char> linux_sh_x64();

std::vector<unsigned char> linux_sh_x86();

} // namespace ctf
