#include "bin_utils.hpp"
#include <LIEF/LIEF.hpp>
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

/* ------------------------------------------------------------------ */
/* small helpers                                                       */

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

address_map extract_strings(const LIEF::Binary &bin, size_t min_len = 4) {
    address_map all;
    for (const auto &sec : bin.sections())
        all.merge(extract_strings_from_section(
            sec.content(), sec.virtual_address(), min_len
        ));
    return all;
}

/* ------------------------------------------------------------------ */

struct Binary::Impl {
    fs::path path;
    std::unique_ptr<LIEF::Binary> bin;
    Endian endian    = Endian::Little;
    Bits bits        = Bits::Bits64;
    bool has_canary  = false;
    size_t base_addr = 0;
    address_map syms;
    mutable std::optional<address_map> strings_cache;

    explicit Impl(const fs::path &p)
        : path(p), bin(LIEF::Parser::parse(p.string())) {
        if (!fs::exists(path))
            throw std::runtime_error(
                fmt::format("File doesn't exist: {}", path.string())
            );

        bits   = bin->header().is_64() ? Bits::Bits64 : Bits::Bits32;
        endian = bin->header().endianness() == LIEF::ENDIAN_BIG
                     ? Endian::Big
                     : Endian::Little;

        for (const auto &s : bin->symbols()) {
            const auto &name = s.name();
            if (name.starts_with("__stack_chk") ||
                name.starts_with("__security_cookie"))
                has_canary = true;
            if (s.value())
                syms[name] = s.value();
        }
    }
};

/* ------------------------------------------------------------------ */
/*  public interface                                                   */

Binary::Binary(const fs::path &p) : pimpl(std::make_shared<Impl>(p)) {}

Bits Binary::bits() const { return pimpl->bits; }
fs::path Binary::path() const { return pimpl->path; }
void *Binary::bin() { return pimpl->bin.get(); }
address_map &Binary::symbols() const { return pimpl->syms; }

std::vector<size_t> Binary::search(std::initializer_list<std::string_view> seq
) {
    auto tgt = make_cstn_target(
        pimpl->bin->header().architecture(), pimpl->bin->header().modes(), pimpl->bin->header().endianness()
    );

    auto eng =
        cstn::Engine::create({.arch = tgt.arch, .syntax = cstn::Syntax::Intel, .cpu = tgt.cpu, .features = tgt.features})
            .unwrap();

    std::vector<std::string> pat(seq.begin(), seq.end());
    std::vector<size_t> hits;

    for (const auto &sec : pimpl->bin->sections()) {
        /* --- executable? --------------------------------------------- */
        const auto *elf  = dynamic_cast<const LIEF::ELF::Section *>(&sec);
        const auto *pe   = dynamic_cast<const LIEF::PE::Section *>(&sec);
        const auto *mach = dynamic_cast<const LIEF::MachO::Section *>(&sec);

        bool exec =
            (elf && elf->has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR)) ||
            (pe && pe->has_characteristic(
                       LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE
                   )) ||
            (mach &&
             mach->has(
                 LIEF::MachO::MACHO_SECTION_FLAGS::S_ATTR_PURE_INSTRUCTIONS
             ));

        if (!exec)
            continue;

        /* --- disassemble --------------------------------------------- */
        auto il = eng.disassemble(
                         std::string_view(
                             std::bit_cast<const char *>(sec.content().data()),
                             sec.content().size()
                         ),
                         sec.virtual_address(),
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

bool Binary::position_independent() const { return pimpl->bin->is_pie(); }
bool Binary::executable_stack() const { return pimpl->bin->has_nx(); }

Architecture Binary::arch() const {
    using A = LIEF::ARCHITECTURES;
    switch (pimpl->bin->header().architecture()) {
    case A::ARCH_X86:
        return pimpl->bin->header().is_64() ? Architecture::X86_64
                                            : Architecture::X86;
    case A::ARCH_ARM:
        return Architecture::Arm;
    case A::ARCH_ARM64:
        return Architecture::Aarch64;
    default:
        return Architecture::Other;
    }
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
        pimpl->strings_cache = extract_strings(*pimpl->bin);
    return *pimpl->strings_cache;
}

} // namespace xcft
