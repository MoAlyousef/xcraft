#include <LIEF/LIEF.hpp>
#include <ctf/macho.hpp>
#include <fmt/core.h>
#include <magic_enum.hpp>
#include <optional>

namespace ctf {
using opt_map = std::optional<address_map>;

static opt_map STUBS = std::nullopt;

static opt_map IAT = std::nullopt;

static address_map populate_symbol_stubs(const LIEF::MachO::Binary &binary) {
    address_map stubs;

    for (const auto &symbol : binary.symbols()) {
        if (symbol.is_external()) {
            std::string name = symbol.name();
            if (!name.empty()) {
                stubs[name] = symbol.value();
            }
        }
    }

    return stubs;
}

static address_map populate_iat(const LIEF::MachO::Binary &binary) {
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

MachO::MachO(fs::path path)
    : Binary(std::move(path)),
      pimpl(std::make_shared<MachO::Impl>(dynamic_cast<LIEF::MachO::Binary *>(
          static_cast<LIEF::Binary *>(Binary::bin())
      ))) {
    pimpl->init();
    fmt::println("MachO:   {}", fs::canonical(Binary::path()).string());
    fmt::println("Bits:    {}", static_cast<int>(bits()));
    fmt::println("Arch:    {}", magic_enum::enum_name(arch()));
    fmt::println("Endian:  {}", magic_enum::enum_name(endianness()));
    fmt::println("Static:  {}", pimpl->dynamic);
    fmt::println("NX:      {}", executable_stack());
    fmt::println(
        "Stack:   {}", stack_canaries() ? "canary found" : "No canary found"
    );
    fmt::println("Pie:     {}", position_independent());
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
    if (!STUBS)
        (void)stubs();
    for (auto &[name, offset] : *STUBS) {
        offset += delta;
    }
    if (!IAT)
        (void)iat();
    for (auto &[name, offset] : *IAT) {
        offset += delta;
    }
    return Binary::set_address(addr);
}
} // namespace ctf