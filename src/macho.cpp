#include <LIEF/LIEF.hpp>
#include <fmt/color.h>
#include <fmt/core.h>
#include <magic_enum.hpp>
#include <optional>
#include <xcraft/macho.hpp>

namespace xcft {
using opt_map = std::optional<address_map>;

namespace {

opt_map STUBS = std::nullopt;

opt_map IAT = std::nullopt;

address_map populate_symbol_stubs(const LIEF::MachO::Binary &binary) {
    address_map stubs;

    for (const auto &symbol : binary.symbols()) {
        if (symbol.is_external()) {
            const std::string &name = symbol.name();
            if (!name.empty()) {
                stubs[name] = symbol.value();
            }
        }
    }

    return stubs;
}

address_map populate_iat(const LIEF::MachO::Binary &binary) {
    address_map iat;

    for (const auto &relocation : binary.relocations()) {
        const auto *symbol = relocation.symbol();
        if (symbol != nullptr) {
            std::string name = symbol->name();
            if (!name.empty()) {
                iat[name] = relocation.address();
            }
        }
    }

    return iat;
}
} // namespace

struct MachO::Impl {
    LIEF::MachO::Binary *bin;
    bool dynamic = false;
    explicit Impl(LIEF::MachO::Binary *bin_) : bin(bin_) {}
    void init() {
        for (const auto &command : bin->commands()) {
            if (command.command() ==
                LIEF::MachO::LOAD_COMMAND_TYPES::LC_LOAD_DYLIB) {
                dynamic = true;
            }
        }
    }
};

MachO::MachO(const fs::path &path)
    : Binary(path),
      pimpl(
          std::make_shared<MachO::Impl>(dynamic_cast<LIEF::MachO::Binary *>(
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

bool MachO::statically_linked() const { return !pimpl->dynamic; }

address_map &MachO::stubs() const {
    if (!STUBS) {
        STUBS = populate_symbol_stubs(*pimpl->bin);
    }
    return *STUBS;
}

address_map &MachO::iat() const {
    if (!IAT) {
        IAT = populate_iat(*pimpl->bin);
    }
    return *IAT;
}

size_t MachO::set_address(size_t addr) {
    auto delta = addr - address();
    for (auto &[name, offset] : stubs()) {
        offset += delta;
    }
    for (auto &[name, offset] : iat()) {
        offset += delta;
    }
    return Binary::set_address(addr);
}
} // namespace xcft