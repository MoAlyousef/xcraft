#include <LIEF/LIEF.hpp>
#include <fmt/color.h>
#include <fmt/core.h>
#include <magic_enum.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <xcraft/elf.hpp>
#include <xcraft/enums.hpp>

using opt_map = std::optional<address_map>;

namespace {
opt_map PLT = std::nullopt;

opt_map GOT = std::nullopt;

address_map populate_plt(const LIEF::ELF::Binary &binary) {
    address_map plt;

    const auto *plt_section = binary.get_section(".plt");
    if (plt_section == nullptr) {
        throw std::runtime_error(".plt section not found");
    }

    size_t index = 0;
    for (const auto &relocation : binary.pltgot_relocations()) {
        const auto *symbol = relocation.symbol();
        if (symbol == nullptr) {
            continue;
        }

        std::string name = symbol->name();
        if (!name.empty()) {
            uint64_t plt_address = plt_section->virtual_address() +
                                   plt_section->entry_size() * (index + 1);
            plt[name] = plt_address;
        }
        index++;
    }

    return plt;
}

address_map populate_got(const LIEF::ELF::Binary &binary) {
    address_map got;
    for (const auto &r : binary.pltgot_relocations()) {
        auto s         = r.symbol();
        got[s->name()] = r.address();
    }

    return got;
}
} // namespace

namespace xcft {

struct ELF::Impl {
    LIEF::ELF::Binary *bin;
    bool dynamic    = false;
    RelroType relro = RelroType::NoRelro;
    explicit Impl(LIEF::ELF::Binary *bin_) : bin(bin_) {}
    void init() {
        dynamic = !bin->dynamic_entries().empty() ||
                  !bin->dynamic_symbols().empty() ||
                  bin->has(LIEF::ELF::DYNAMIC_TAGS::DT_NEEDED);

        bool has_relro_segment = false;
        for (const auto &segment : bin->segments()) {
            if (segment.type() == LIEF::ELF::SEGMENT_TYPES::PT_GNU_RELRO) {
                has_relro_segment = true;
                break;
            }
        }

        bool has_bind_now = false;
        for (const auto &entry : bin->dynamic_entries()) {
            if (entry.tag() == LIEF::ELF::DYNAMIC_TAGS::DT_FLAGS) {
                const auto &flags =
                    dynamic_cast<const LIEF::ELF::DynamicEntryFlags &>(entry);
                if (flags.has(LIEF::ELF::DYNAMIC_FLAGS::DF_BIND_NOW)) {
                    has_bind_now = true;
                    break;
                }
            } else if (entry.tag() == LIEF::ELF::DYNAMIC_TAGS::DT_FLAGS_1) {
                const auto &flags =
                    dynamic_cast<const LIEF::ELF::DynamicEntryFlags &>(entry);
                if (flags.has(LIEF::ELF::DYNAMIC_FLAGS_1::DF_1_NOW)) {
                    has_bind_now = true;
                    break;
                }
            }
        }

        if (has_relro_segment) {
            if (has_bind_now) {
                relro = RelroType::FullRelro;
            } else {
                relro = RelroType::PartialRelro;
            }
        }
    }
};

ELF::ELF(const fs::path &path)
    : Binary(path),
      pimpl(
          std::make_shared<ELF::Impl>(dynamic_cast<LIEF::ELF::Binary *>(
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
    fmt::println(
        "Relro:           {}",
        relro() == RelroType::FullRelro
            ? fmt::styled("Full Relro   ", fmt::fg(fmt::color::green))
            : (relro() == RelroType::PartialRelro
                   ? fmt::styled("Partial Relro", fmt::fg(fmt::color::yellow))

                   : fmt::styled("No Relro     ", fmt::fg(fmt::color::red)))
    );
    fmt::println("");
}

RelroType ELF::relro() const { return pimpl->relro; }

bool ELF::statically_linked() const { return !pimpl->dynamic; }

address_map &ELF::got() const {
    if (!GOT) {
        GOT = populate_got(*pimpl->bin);
    }
    return *GOT;
}

address_map &ELF::plt() const {
    if (!PLT) {
        PLT = populate_plt(*pimpl->bin);
    }
    return *PLT;
}

size_t ELF::set_address(size_t addr) {
    auto delta = addr - address();
    for (auto &[name, offset] : got()) {
        offset += delta;
    }
    for (auto &[name, offset] : plt()) {
        offset += delta;
    }
    return Binary::set_address(addr);
}
} // namespace xcft
