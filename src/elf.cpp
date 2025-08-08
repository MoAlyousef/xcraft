#include "llvm_object_utils.hpp"
#include <fmt/color.h>
#include <fmt/core.h>
#include <magic_enum.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <xcraft/elf.hpp>
#include <xcraft/enums.hpp>

using opt_map = std::optional<address_map>;

namespace xcft {

struct ELF::Impl {
    std::unique_ptr<LLVMObjectFile> obj;
    bool dynamic    = false;
    RelroType relro = RelroType::NoRelro;
    mutable opt_map plt_cache = std::nullopt;
    mutable opt_map got_cache = std::nullopt;
    
    explicit Impl(const fs::path& path) : obj(std::make_unique<LLVMObjectFile>(path)) {}
    
    void init() {
        dynamic = obj->is_dynamically_linked();
        
        if (obj->has_full_relro()) {
            relro = RelroType::FullRelro;
        } else if (obj->has_relro()) {
            relro = RelroType::PartialRelro;
        } else {
            relro = RelroType::NoRelro;
        }
    }
};

ELF::ELF(const fs::path &p) : Binary(p) {
    auto info = static_cast<LLVMObjectFile*>(bin())->get_info();
    if (info.format != BinaryFormat::ELF) {
        throw std::runtime_error("File is not an ELF binary");
    }
    
    pimpl = std::make_shared<ELF::Impl>(p);
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

address_map &ELF::plt() const {
    if (!pimpl->plt_cache) {
        pimpl->plt_cache = pimpl->obj->get_plt();
    }
    return *pimpl->plt_cache;
}

address_map &ELF::got() const {
    if (!pimpl->got_cache) {
        pimpl->got_cache = pimpl->obj->get_got();
    }
    return *pimpl->got_cache;
}

bool ELF::statically_linked() const {
    return !pimpl->dynamic;
}

RelroType ELF::relro() const {
    return pimpl->relro;
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