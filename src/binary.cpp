#include "bin_utils.hpp"
#include "llvm_object_utils.hpp"
#include <bit>
#include <cornerstone/cornerstone.hpp>
#include <fmt/format.h>
#include <fmt/ostream.h>
#include <iostream>
#include <magic_enum.hpp>
#include <optional>
#include <span>
#include <stdexcept>
#include <xcraft/binary.hpp>
namespace xcft {

// NOLINTNEXTLINE
static bool printable(unsigned char c) { return c >= 32 && c <= 126; }

address_map extract_strings_from_section(
    std::span<const unsigned char> buf, size_t vaddr, size_t min_len = 4
) {
    address_map out;
    const unsigned char *cur = buf.data(), *end = cur + buf.size(),
                        *beg = nullptr;

    while (cur < end) {
        if (printable(*cur)) {
            if (!beg)
                beg = cur;
        } else {
            if (beg && static_cast<size_t>(cur - beg) >= min_len) {
                std::string s(std::bit_cast<const char *>(beg), cur - beg);
                out[s] = vaddr + (beg - buf.data());
            }
            beg = nullptr;
        }
        ++cur;
    }
    if (beg && static_cast<size_t>(cur - beg) >= min_len) {
        std::string s(std::bit_cast<const char *>(beg), cur - beg);
        out[s] = vaddr + (beg - buf.data());
    }
    return out;
}

// This function is no longer needed as LLVM Object wrapper handles string extraction

struct Binary::Impl {
    fs::path path;
    std::unique_ptr<LLVMObjectFile> llvm_obj;   // LLVM Object wrapper
    Endian endian    = Endian::Little;
    Bits bits        = Bits::Bits64;
    bool has_canary  = false;
    size_t base_addr = 0;
    address_map syms;
    mutable std::optional<address_map> strings_cache;

    explicit Impl(const fs::path &p)
        : path(p), llvm_obj(std::make_unique<LLVMObjectFile>(p)) {
        if (!fs::exists(path))
            throw std::runtime_error(
                fmt::format("File doesn't exist: {}", path.string())
            );

        // Use LLVM Object for basic info
        auto info = llvm_obj->get_info();
        bits = info.is_64bit ? Bits::Bits64 : Bits::Bits32;
        endian = info.endianness == LLVMEndianness::Big ? Endian::Big : Endian::Little;
        
        // Use LLVM Object for symbols
        syms = llvm_obj->get_symbols();
        
        // Check for stack canaries
        has_canary = llvm_obj->has_stack_canaries();
    }
};

Binary::Binary(const fs::path &p) : pimpl(std::make_shared<Impl>(p)) {}

Bits Binary::bits() const { return pimpl->bits; }
fs::path Binary::path() const { return pimpl->path; }
void *Binary::bin() { return pimpl->llvm_obj.get(); }
address_map &Binary::symbols() const { return pimpl->syms; }

std::vector<size_t> Binary::search(std::initializer_list<std::string_view> seq
) {
    auto info = pimpl->llvm_obj->get_info();
    
    cstn::Opts opts{};
    cstn::Arch arch;
    switch (info.arch) {
        case Architecture::X86:
        case Architecture::X86_64:
            arch = cstn::Arch::x86_64; break;
        case Architecture::Arm:
            arch = cstn::Arch::arm; break;
        case Architecture::Aarch64:
            arch = cstn::Arch::aarch64; break;
        default:
            arch = cstn::Arch::x86_64; break;
    }
    
    opts.cpu = info.is_64bit ? "x86-64" : "i386";
    opts.features = "";
    auto eng = cstn::Engine::create(arch, {.syntax = cstn::Syntax::Intel, .cpu = opts.cpu, .features = opts.features})
                   .unwrap();

    std::vector<std::string> pat(seq.begin(), seq.end());
    std::vector<size_t> hits;

    auto sections = pimpl->llvm_obj->get_executable_sections();
    for (const auto &sec : sections) {
        if (!sec.executable || sec.data.empty())
            continue;

        auto il = eng.disassemble(
                         std::string_view(
                             reinterpret_cast<const char *>(sec.data.data()),
                             sec.data.size()
                         ),
                         sec.address,
                         false
        )
                      .unwrap();
        auto &ins = il.insns;
        if (ins.empty())
            continue;

        size_t idx = 0, first = 0;
        for (const auto &i : ins) {
            std::string full =
                i.op_str.empty() ? i.mnemonic : i.mnemonic + ' ' + i.op_str;
            if (full == pat[idx]) {
                if (idx == 0)
                    first = i.address;
                if (++idx == pat.size()) {
                    hits.push_back(first);
                    idx = 0;
                }
            } else {
                idx = 0;
            }
        }
    }
    return hits;
}

bool Binary::position_independent() const { 
    return pimpl->llvm_obj->is_position_independent(); 
}

bool Binary::executable_stack() const { 
    return pimpl->llvm_obj->has_executable_stack(); 
}

Architecture Binary::arch() const {
    auto info = pimpl->llvm_obj->get_info();
    return info.arch;
}

bool Binary::stack_canaries() const { return pimpl->has_canary; }
Endian Binary::endianness() const { return pimpl->endian; }

size_t Binary::address() const { return pimpl->base_addr; }

size_t Binary::set_address(size_t addr) {
    size_t delta     = addr - pimpl->base_addr;
    pimpl->base_addr = addr;

    for (auto &[_, offs] : pimpl->syms)
        offs += delta;
    for (auto &[_, offs] : strings())
        offs += delta;
    return pimpl->base_addr;
}

address_map &Binary::strings() const {
    if (!pimpl->strings_cache)
        pimpl->strings_cache = pimpl->llvm_obj->extract_strings();
    return *pimpl->strings_cache;
}

} // namespace xcft
