#include "llvm_object_utils.hpp"
#include <fmt/color.h>
#include <fmt/core.h>
#include <magic_enum.hpp>
#include <optional>
#include <stdexcept>
#include <xcraft/pe.hpp>

using opt_map = std::optional<address_map>;

namespace xcft {

struct PE::Impl {
    std::unique_ptr<LLVMObjectFile> obj;
    mutable opt_map iat_cache = std::nullopt;
    mutable opt_map ilt_cache = std::nullopt;
    
    explicit Impl(const fs::path& path) : obj(std::make_unique<LLVMObjectFile>(path)) {}
};

PE::PE(const fs::path &p) : Binary(p) {
    auto info = static_cast<LLVMObjectFile*>(bin())->get_info();
    if (info.format != BinaryFormat::PE) {
        throw std::runtime_error("File is not a PE binary");
    }
    
    pimpl = std::make_shared<PE::Impl>(p);
    
    fmt::println("PE:              {}", fs::canonical(Binary::path()).string());
    fmt::println("Bits:            {}", static_cast<int>(bits()));
    fmt::println("Arch:            {}", magic_enum::enum_name(arch()));
    fmt::println("Endian:          {}", magic_enum::enum_name(endianness()));
    fmt::println("Static:          {}", statically_linked() ? "Yes" : "No");
    fmt::println(
        "NX:              {}",
        executable_stack()
            ? fmt::styled(
                  "NX Disabled", fmt::fg(fmt::color::red)
              )
            : fmt::styled(
                  "NX Enabled ", fmt::fg(fmt::color::green)
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
            ? fmt::styled("PIE Enabled ", fmt::fg(fmt::color::green))
            : fmt::styled("No PIE      ", fmt::fg(fmt::color::red))
    );
    fmt::println("");
}

address_map &PE::iat() const {
    if (!pimpl->iat_cache) {
        pimpl->iat_cache = pimpl->obj->get_iat();
    }
    return *pimpl->iat_cache;
}

address_map &PE::ilt() const {
    if (!pimpl->ilt_cache) {
        // For PE files, ILT is closely related to IAT
        // This would need more specific PE parsing, but use IAT as placeholder
        pimpl->ilt_cache = pimpl->obj->get_iat();
    }
    return *pimpl->ilt_cache;
}

bool PE::statically_linked() const {
    // Check if this PE has any import directories
    auto iat = pimpl->obj->get_iat();
    return iat.empty(); // If no imports, it's statically linked
}

size_t PE::set_address(size_t addr) {
    auto delta = addr - address();
    for (auto &[name, offset] : iat()) {
        offset += delta;
    }
    for (auto &[name, offset] : ilt()) {
        offset += delta;
    }
    return Binary::set_address(addr);
}

} // namespace xcft