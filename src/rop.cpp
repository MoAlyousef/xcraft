#include "bin_utils.hpp"
#include "llvm_object_utils.hpp"
#include <algorithm>
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
    constexpr size_t depth = 13;
    LLVMObjectFile obj(path);
    auto info = obj.get_info();
    
    cstn::Opts opts{};
    // Convert LLVM Object info to cornerstone target
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
    auto eng = cstn::Engine::create(arch, opts).unwrap();

    std::vector<Gadget> gadgets;
    std::set<uint64_t> processed_addresses;

    auto sections = obj.get_executable_sections();
    for (const auto &section : sections) {
        if (section.executable && !section.data.empty()) {
            auto il = eng.disassemble(
                             std::string_view(
                                 reinterpret_cast<const char *>(section.data.data()),
                                 section.data.size()
                             ),
                             section.address
            )
                          .unwrap();
            auto &insn = il.insns;
            if (!insn.empty()) {
                // Find all gadget-ending instructions
                for (size_t i = 0; i < insn.size(); i++) {
                    if (is_gadget_end(insn[i]) && 
                        processed_addresses.find(insn[i].address) == processed_addresses.end()) {
                        
                        // Walk backwards to find the start of the gadget
                        size_t start = i;
                        while (start > 0 && 
                               (insn[i].address - insn[start - 1].address) < depth) {
                            start--;
                            // Stop if we encounter another gadget-ending instruction
                            if (is_gadget_end(insn[start])) {
                                start++;
                                break;
                            }
                        }

                        // Build the single gadget from start to end
                        std::vector<Instruction> instructions;
                        for (size_t j = start; j <= i; j++) {
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
                            processed_addresses.insert(insn[j].address);
                        }
                        
                        if (!instructions.empty()) {
                            gadgets.push_back(Gadget{instructions});
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
            insn_asm.begin(), insn_asm.end(), split.begin(), split.end(),
            [](const std::string& a, const std::string_view& b) { return a == b; }
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