#include <LIEF/LIEF.hpp>
#include <ctf/elf.hpp>
#include <ctf/enums.hpp>
#include <fmt/core.h>
#include <magic_enum.hpp>
#include <optional>
#include <stdexcept>
#include <string>

using opt_map = std::optional<address_map>;

static opt_map PLT = std::nullopt;

static opt_map GOT = std::nullopt;

static address_map populate_plt(const LIEF::ELF::Binary &binary) {
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

static address_map populate_got(const LIEF::ELF::Binary &binary) {
    address_map got;
    for (const auto &r : binary.pltgot_relocations()) {
        auto s         = r.symbol();
        got[s->name()] = r.address();
    }

    return got;
}

namespace ctf {

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

ELF::ELF(fs::path path)
    : Binary(std::move(path)),
      pimpl(std::make_shared<ELF::Impl>(dynamic_cast<LIEF::ELF::Binary *>(
          static_cast<LIEF::Binary *>(Binary::bin())
      ))) {
    pimpl->init();
    fmt::println("Elf:     {}", fs::canonical(Binary::path()).string());
    fmt::println("Arch:    {}", magic_enum::enum_name(arch()));
    fmt::println("Endian:  {}", magic_enum::enum_name(endianness()));
    fmt::println("Static:  {}", pimpl->dynamic);
    fmt::println("NX:      {}", executable_stack());
    fmt::println(
        "Stack:   {}", stack_canaries() ? "canary found" : "No canary found"
    );
    fmt::println("Pie:     {}", position_independent());
    fmt::println("Relro:   {}", magic_enum::enum_name(relro()));
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
    if (!GOT)
        (void)got();
    for (auto &[name, offset] : *GOT) {
        offset += delta;
    }
    if (!PLT)
        (void)plt();
    for (auto &[name, offset] : *PLT) {
        offset += delta;
    }
    return Binary::set_address(addr);
}
} // namespace ctf
