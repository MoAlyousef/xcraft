#include <LIEF/LIEF.hpp>
#include <ctf/pe.hpp>
#include <fmt/core.h>
#include <magic_enum.hpp>
#include <optional>

namespace ctf {

using opt_map = std::optional<address_map>;

static opt_map IAT = std::nullopt;

static opt_map ILT = std::nullopt;

static address_map populate_iat(const LIEF::PE::Binary &binary) {
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

static address_map populate_ilt(const LIEF::PE::Binary &binary) {
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

struct PE::Impl {
    LIEF::PE::Binary *bin;
    bool dynamic = false;
    explicit Impl(LIEF::PE::Binary *bin_) : bin(bin_) {}
    void init() { dynamic = bin->has_imports(); }
};

PE::PE(fs::path path)
    : Binary(std::move(path)),
      pimpl(std::make_shared<PE::Impl>(dynamic_cast<LIEF::PE::Binary *>(
          static_cast<LIEF::Binary *>(Binary::bin())
      ))) {
    pimpl->init();
    fmt::println("PE:      {}", fs::canonical(Binary::path()).string());
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
} // namespace ctf