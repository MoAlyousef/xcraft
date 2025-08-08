#include "llvm_object_utils.hpp"
#include <fmt/color.h>
#include <fmt/core.h>
#include <magic_enum.hpp>
#include <optional>
#include <stdexcept>
#include <xcraft/macho.hpp>

using opt_map = std::optional<address_map>;

namespace xcft {

struct MachO::Impl {
    std::unique_ptr<LLVMObjectFile> obj;
    bool dynamic = false;
    mutable opt_map stubs_cache = std::nullopt;
    mutable opt_map iat_cache = std::nullopt;
    
    explicit Impl(const fs::path& path) : obj(std::make_unique<LLVMObjectFile>(path)) {}
    
    void init() {
        // Check if dynamically linked by looking for external symbols
        auto stubs = obj->get_symbol_stubs();
        dynamic = !stubs.empty();
    }
};

MachO::MachO(const fs::path &p) : Binary(p) {
    auto info = static_cast<LLVMObjectFile*>(bin())->get_info();
    if (info.format != BinaryFormat::MachO) {
        throw std::runtime_error("File is not a Mach-O binary");
    }
    
    pimpl = std::make_shared<MachO::Impl>(p);
    pimpl->init();
    
    fmt::println("Mach-O:          {}", fs::canonical(Binary::path()).string());
    fmt::println("Bits:            {}", static_cast<int>(bits()));
    fmt::println("Arch:            {}", magic_enum::enum_name(arch()));
    fmt::println("Endian:          {}", magic_enum::enum_name(endianness()));
    fmt::println("Static:          {}", statically_linked() ? "Yes" : "No");
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

address_map &MachO::stubs() const {
    if (!pimpl->stubs_cache) {
        pimpl->stubs_cache = pimpl->obj->get_symbol_stubs();
    }
    return *pimpl->stubs_cache;
}

address_map &MachO::iat() const {
    if (!pimpl->iat_cache) {
        // For Mach-O, the "iat" concept maps to symbol stubs  
        pimpl->iat_cache = pimpl->obj->get_symbol_stubs();
    }
    return *pimpl->iat_cache;
}

bool MachO::statically_linked() const {
    return !pimpl->dynamic;
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