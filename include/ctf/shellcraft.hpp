#pragma once

#include <ctf/enums.hpp>
#include <optional>
#include <string>

namespace ctf {

std::string disassemble(
    std::string_view code,
    Architecture arch,
    std::optional<size_t> address = std::nullopt
);

std::string disassemble(
    std::string_view code, std::optional<size_t> address = std::nullopt
);

std::string assemble(const char *code, Architecture arch);

std::string assemble(const char *code);

std::string linux_sh_x64();

std::string linux_sh_x86();

} // namespace ctf
