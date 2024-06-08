#include "bin_utils.hpp"
#include <LIEF/LIEF.hpp>
#include <ctf/binary.hpp>
#include <fmt/format.h>
#include <optional>
#include <span>
#include <stdexcept>

namespace ctf {
using opt_map = std::optional<address_map>;

static opt_map STRINGS = std::nullopt;

static bool is_printable_ascii(unsigned char c) {
    constexpr unsigned char min_printable_char = 32;
    constexpr unsigned char max_printable_char = 126;
    return c >= min_printable_char && c <= max_printable_char;
}
address_map extract_strings_from_section(
    std::span<const unsigned char> content,
    size_t virtual_address,
    size_t min_length = 4
) {
    address_map strings;
    const unsigned char *p     = content.data();
    const unsigned char *end   = p + content.size();
    const unsigned char *start = nullptr;

    while (p < end) {
        if (is_printable_ascii(*p)) {
            if (start == nullptr) {
                start = p;
            }
        } else {
            if (start != nullptr && (p - start) >= min_length) {
                std::string str(
                    reinterpret_cast<const char *>(start), p - start
                );
                size_t address = virtual_address + (start - content.data());
                strings[str]   = address;
            }
            start = nullptr;
        }
        ++p;
    }

    if (start != nullptr && (p - start) >= min_length) {
        std::string str(reinterpret_cast<const char *>(start), p - start);
        size_t address = virtual_address + (start - content.data());
        strings[str]   = address;
    }

    return strings;
}

address_map extract_strings(const LIEF::Binary &binary, size_t min_length = 4) {
    address_map all_strings;

    for (const auto &section : binary.sections()) {
        auto section_strings = extract_strings_from_section(
            section.content(), section.virtual_address(), min_length
        );
        all_strings.insert(section_strings.begin(), section_strings.end());
    }

    return all_strings;
}

struct Binary::Impl {
    fs::path path_;
    std::unique_ptr<LIEF::Binary> bin;
    Endian endian           = Endian::Little;
    Bits bits               = Bits::Bits64;
    bool has_stack_canaries = false;
    size_t address_         = 0;
    address_map symbols;
    Impl(fs::path path)
        : path_(path), bin(LIEF::Parser::parse(path.string())), symbols{} {
        if (!fs::exists(path_))
            throw std::runtime_error(
                fmt::format("File doesn't exist: {}", path_.string())
            );
        bits   = bin->header().is_64() ? Bits::Bits64 : Bits::Bits32;
        endian = bin->header().endianness() == LIEF::ENDIAN_BIG
                     ? Endian::Big
                     : Endian::Little;
        for (const auto &s : bin->symbols()) {
            auto name = s.name();
            if (name.find("__stack_chk") == 0 ||
                name.find("__security_cookie") == 0)
                has_stack_canaries = true;
            if (s.value())
                symbols[name] = s.value();
        }
    }
};

Binary::~Binary() = default;

Binary::Binary(fs::path path) : pimpl(std::make_shared<Binary::Impl>(path)) {}

Bits Binary::bits() const { return pimpl->bits; }

fs::path Binary::path() const { return pimpl->path_; }

void *Binary::bin() { return pimpl->bin.get(); }

address_map &Binary::symbols() const { return pimpl->symbols; }

std::vector<size_t> Binary::search(std::initializer_list<std::string_view> seq
) {
    auto [arch, mode] = get_capstone_arch(
        pimpl->bin->header().architecture(), pimpl->bin->header().modes()
    );
    csh handle    = 0;
    cs_insn *insn = nullptr;
    size_t count  = 0;

    if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone disassembler.");
    }

    std::vector<size_t> addresses;
    auto sequence = std::vector<std::string>(seq.begin(), seq.end());

    for (const auto &section : pimpl->bin->sections()) {
        count = cs_disasm(
            handle,
            section.content().data(),
            section.content().size(),
            section.virtual_address(),
            0,
            &insn
        );
        if (count > 0) {
            size_t match_idx     = 0;
            size_t first_address = 0;

            for (size_t i = 0; i < count; ++i) {
                std::string full_instruction =
                    std::string(insn[i].mnemonic) + " " + insn[i].op_str;
                if (full_instruction == sequence[match_idx]) {
                    if (match_idx == 0) {
                        first_address = insn[i].address;
                    }
                    match_idx++;
                    if (match_idx == sequence.size()) {
                        addresses.push_back(first_address);
                        match_idx = 0;
                    }
                } else {
                    match_idx = 0;
                }
            }
            cs_free(insn, count);
        }
    }

    cs_close(&handle);
    return addresses;
}
bool Binary::position_independent() const { return pimpl->bin->is_pie(); }
bool Binary::executable_stack() const { return pimpl->bin->has_nx(); }
Architecture Binary::arch() const {
    switch (pimpl->bin->header().architecture()) {
    case LIEF::ARCHITECTURES::ARCH_X86:
        if (pimpl->bin->header().is_64())
            return Architecture::X86_64;
        else
            return Architecture::X86;
    case LIEF::ARCHITECTURES::ARCH_ARM:
        return Architecture::Arm;
    case LIEF::ARCHITECTURES::ARCH_ARM64:
        return Architecture::Aarch64;
    default:
        return Architecture::Other;
    }
}

bool Binary::stack_canaries() const { return pimpl->has_stack_canaries; }

Endian Binary::endianness() const { return pimpl->endian; }

size_t Binary::address() const { return pimpl->address_; }

size_t Binary::set_address(size_t addr) {
    auto delta      = addr - pimpl->address_;
    pimpl->address_ = addr;
    for (auto &[name, offset] : pimpl->symbols) {
        offset += delta;
    }
    for (auto &[name, offset] : strings()) {
        offset += delta;
    }
    return pimpl->address_;
}

address_map &Binary::strings() const {
    if (!STRINGS) {
        STRINGS = extract_strings(*pimpl->bin);
    }
    return *STRINGS;
}
} // namespace ctf
