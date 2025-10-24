#include <cornerstone/cornerstone.hpp>
#include <cstring>
#include <fmt/format.h>
#include <stdexcept>
#include <xcraft/context.hpp>
#include <xcraft/enums.hpp>
#include <xcraft/shellcraft.hpp>

namespace {

const char *LINUX_X64_SH = R"lit(push 0x68
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

const char *LINUX_X86_SH = R"lit(push 0x68
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

cstn::Arch convert_arch_to_cs(xcft::Architecture arch) {
    using xcft::Architecture;
    using namespace cstn;
    switch (arch) {
    case Architecture::X86_64:
        return Arch::x86_64;
    case Architecture::X86:
        return Arch::x86;
    case Architecture::Arm:
        return Arch::arm;
    case Architecture::Aarch64:
        return Arch::aarch64;
    case Architecture::Other:
    default:
        throw std::runtime_error("Architecture not implemented!");
    }
}
} // namespace

namespace xcft {

std::string disassemble(
    std::string_view code, Architecture arch, std::optional<size_t> address
) {
    const auto a = convert_arch_to_cs(arch);
    auto engine  = cstn::Engine::create(a).unwrap();
    return engine.disassemble(code, address ? *address : 0)
        .unwrap()
        .pretty_format();
}

std::string disassemble(std::string_view code, std::optional<size_t> address) {
    return disassemble(code, CONTEXT.arch, address);
}

std::string assemble(const char *code, Architecture arch) {
    const auto a = convert_arch_to_cs(arch);
    auto engine  = cstn::Engine::create(a).unwrap();
    return engine.assemble(code).unwrap();
}

std::string assemble(const char *code) { return assemble(code, CONTEXT.arch); }

std::string linux_sh_x64() {
    return assemble(LINUX_X64_SH, Architecture::X86_64);
}

std::string linux_sh_x86() { return assemble(LINUX_X86_SH, Architecture::X86); }
} // namespace xcft
