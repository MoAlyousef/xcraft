#include <LIEF/LIEF.hpp>
#include <fmt/color.h>
#include <fmt/core.h>
#include <magic_enum.hpp>
#include <optional>
#include <xcraft/pe.hpp>

namespace xcft {

using opt_map = std::optional<address_map>;

namespace {

opt_map IAT = std::nullopt;

opt_map ILT = std::nullopt;

address_map populate_iat(const LIEF::PE::Binary &binary) {
    address_map iat;

    for (const auto &import : binary.imports()) {
        for (const auto &entry : import.entries()) {
            std::string name = entry.name();
            if (!name.empty()) {
                iat[name] = entry.iat_address();
            }
        }
    }

    return iat;
}

address_map populate_ilt(const LIEF::PE::Binary &binary) {
    address_map ilt;

    for (const auto &import : binary.imports()) {
        for (const auto &entry : import.entries()) {
            std::string name = entry.name();
            if (!name.empty()) {
                ilt[name] = entry.iat_address();
            }
        }
    }
    return ilt;
}
} // namespace
struct PE::Impl {
    LIEF::PE::Binary *bin;
    bool dynamic = false;
    explicit Impl(LIEF::PE::Binary *bin_) : bin(bin_) {}
    void init() { dynamic = bin->has_imports(); }
};

PE::PE(const fs::path &path)
    : Binary(path),
      pimpl(
          std::make_shared<PE::Impl>(dynamic_cast<LIEF::PE::Binary *>(
              static_cast<LIEF::Binary *>(Binary::bin())
          ))
      ) {
    pimpl->init();
    fmt::println("Elf:             {}", fs::canonical(Binary::path()).string());
    fmt::println("Bits:            {}", static_cast<int>(bits()));
    fmt::println("Arch:            {}", magic_enum::enum_name(arch()));
    fmt::println("Endian:          {}", magic_enum::enum_name(endianness()));
    fmt::println("Static:          {}", pimpl->dynamic ? "No" : "Yes");
    fmt::println(
        "NX:              {}",
        executable_stack()
            ? fmt::styled(
                  "NX unknown - GNU_STACK missing", fmt::fg(fmt::color::red)
              )
            : fmt::styled(
                  "NX Enabled                    ", fmt::fg(fmt::color::green)
              )
    );
    fmt::println(
        "Stack:           {}",
        stack_canaries()
            ? fmt::styled("Canary found   ", fmt::fg(fmt::color::green))
            : fmt::styled("No canary found", fmt::fg(fmt::color::red))
    );
    fmt::println(
        "PIE:             {}",
        position_independent()
            ? fmt::styled("PIE Enabled      ", fmt::fg(fmt::color::green))
            : fmt::styled("No PIE (0x400000)", fmt::fg(fmt::color::red))
    );
    fmt::println("");
}

bool PE::statically_linked() const { return !pimpl->dynamic; }

address_map &PE::ilt() const {
    if (!ILT) {
        ILT = populate_ilt(*pimpl->bin);
    }
    return *ILT;
}

address_map &PE::iat() const {
    if (!IAT) {
        IAT = populate_iat(*pimpl->bin);
    }
    return *IAT;
}

size_t PE::set_address(size_t addr) {
    auto delta = addr - address();
    for (auto &[name, offset] : ilt()) {
        offset += delta;
    }
    for (auto &[name, offset] : iat()) {
        offset += delta;
    }
    return Binary::set_address(addr);
}
} // namespace xcft