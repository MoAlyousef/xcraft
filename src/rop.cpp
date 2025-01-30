#include "bin_utils.hpp"
#include <capstone/capstone.h>
#include <ctf/rop.hpp>
#include <fmt/format.h>
#include <span>
#include <stdexcept>
#include <utility>

namespace ctf {

namespace {
bool is_gadget_end(const cs_insn &insn) {
    return strcmp(insn.mnemonic, "ret") == 0 ||
           strcmp(insn.mnemonic, "call") == 0 ||
           strcmp(insn.mnemonic, "syscall") == 0 ||
           strcmp(insn.mnemonic, "int") == 0 || strcmp(insn.mnemonic, "j") == 0;
}

std::vector<Gadget> extract_rop_gadgets(const fs::path &path) {
    constexpr size_t depth               = 13;
    std::unique_ptr<LIEF::Binary> reader = LIEF::Parser::parse(path.string());
    auto header                          = reader->header();
    auto [arch, mode] =
        get_capstone_arch(header.architecture(), header.modes());
    csh handle = 0;
    if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone disassembler.");
    }

    std::vector<Gadget> gadgets;
    cs_insn *insn = nullptr;
    size_t count  = 0;

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
            count = cs_disasm(
                handle,
                section.content().data(),
                section.size(),
                section.virtual_address(),
                0,
                &insn
            );
            if (count > 0) {
                for (size_t i = 0; i < count; i++) {
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
                                insn[j].bytes, insn[j].bytes + insn[j].size
                            );
                            instruction.assembly = insn[j].mnemonic;
                            if (strlen(insn[j].op_str) != 0) {
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
                cs_free(insn, count);
            }
        }
    }

    cs_close(&handle);
    return gadgets;
}

std::vector<size_t> find_rop_gadget(
    std::span<ctf::Gadget> gadgets, std::initializer_list<std::string_view> seq
) {
    std::vector<size_t> addresses;
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
            addresses.push_back(insn[d].address);
    }
    return addresses;
}
}

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
} // namespace ctf