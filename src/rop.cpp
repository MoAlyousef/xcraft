#include "bin_utils.hpp"
#include <cornerstone/cornerstone.hpp>
#include <fmt/format.h>
#include <set>
#include <span>
#include <stdexcept>
#include <utility>
#include <xcraft/rop.hpp>

namespace xcft {

namespace {
bool is_gadget_end(const cstn::Instruction &insn) {
    return insn.mnemonic == "ret" || insn.mnemonic == "call" ||
           insn.mnemonic == "syscall" || insn.mnemonic == "int" ||
           insn.mnemonic.starts_with("j");
}

std::vector<Gadget> extract_rop_gadgets(const fs::path &path) {
    constexpr size_t depth               = 13;
    std::unique_ptr<LIEF::Binary> reader = LIEF::Parser::parse(path.string());
    auto header                          = reader->header();
    cstn::Opts opts{};
    auto tgt = make_cstn_target(
        header.architecture(), header.modes(), header.endianness()
    );
    opts.cpu      = tgt.cpu;
    opts.features = tgt.features;
    auto eng      = cstn::Engine::create(tgt.arch, opts).unwrap();

    std::vector<Gadget> gadgets;

    for (auto &section : reader->sections()) {
        auto elf_sec = dynamic_cast<LIEF::ELF::Section *>(&section);
        auto pe_sec  = dynamic_cast<LIEF::PE::Section *>(&section);
        auto m_sec   = dynamic_cast<LIEF::MachO::Section *>(&section);
        if ((elf_sec &&
             elf_sec->has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR)) ||
            (pe_sec && pe_sec->has_characteristic(
                           LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE
                       )) ||
            (m_sec &&
             m_sec->has(
                 LIEF::MachO::MACHO_SECTION_FLAGS::S_ATTR_PURE_INSTRUCTIONS
             ))) {
            auto il = eng.disassemble(
                             std::string_view(
                                 // NOLINTNEXTLINE
                                 reinterpret_cast<const char *>(
                                     section.content().data()
                                 ),
                                 section.size()
                             ),
                             section.virtual_address()
            )
                          .unwrap();
            auto &insn = il.insns;
            if (!insn.empty()) {
                for (size_t i = 0; i < insn.size(); i++) {
                    if (std::string_view(insn[i].mnemonic) == "ret") {
                        size_t start = i;
                        while (start > 0 && (insn[i].address -
                                             insn[start].address) < depth) {
                            start--;
                        }

                        std::vector<Instruction> instructions;
                        for (size_t j = start + 1; j <= i; j++) {
                            Instruction instruction;
                            instruction.address = insn[j].address;
                            instruction.bytes   = std::string(
                                // NOLINTNEXTLINE
                                reinterpret_cast<const char *>(
                                    insn[j].bytes.data()
                                ),
                                insn[j].bytes.size()
                            );
                            instruction.assembly = insn[j].mnemonic;
                            if (insn[j].op_str.size() != 0) {
                                instruction.assembly += " ";
                                instruction.assembly += insn[j].op_str;
                            }
                            instructions.push_back(instruction);

                            if (is_gadget_end(insn[j])) {
                                gadgets.push_back(Gadget{instructions});
                                instructions.clear();
                            }
                        }
                    }
                }
            }
        }
    }

    return gadgets;
}

std::vector<size_t> find_rop_gadget(
    std::span<xcft::Gadget> gadgets, std::initializer_list<std::string_view> seq
) {
    std::set<size_t> addresses;
    std::vector<std::string_view> split(seq.begin(), seq.end());
    for (auto const &gadget : gadgets) {
        auto insn = gadget.ins;
        if (insn.size() < split.size())
            continue;
        std::vector<std::string> insn_asm;
        insn_asm.reserve(insn.size());
        for (const auto &elem : insn)
            insn_asm.push_back(elem.assembly);
        auto res = std::search(
            insn_asm.begin(), insn_asm.end(), split.begin(), split.end()
        );
        size_t d = std::distance(insn_asm.begin(), res);
        if (d < insn.size())
            addresses.insert(insn[d].address);
    }
    return {addresses.begin(), addresses.end()};
}
} // namespace

ROP::ROP(fs::path p) : path_(std::move(p)) {
    if (!fs::exists(path_))
        throw std::runtime_error(
            fmt::format("File doesn't exist: {}", path_.string())
        );
    gadgets_ = extract_rop_gadgets(path_);
}

const std::vector<Gadget> &ROP::gadgets() { return gadgets_; }

std::vector<size_t> ROP::find_gadget(std::initializer_list<std::string_view> seq
) {
    return find_rop_gadget(gadgets_, seq);
}
} // namespace xcft