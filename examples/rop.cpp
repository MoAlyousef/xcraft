#include <exception>
#include <iostream>
#include <string_view>
#include <xcraft/xcraft.hpp>

int main() {
    auto rop = xcft::ROP("./bin/vuln");
    try {
        auto gadgets = rop.gadgets();
        for (auto g : gadgets) {
            std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0')
                      << g.ins[0].address;
            for (auto i : g.ins)
                std::cout << " " << i.assembly << ";";
            std::cout << std::endl;
        }

        auto addresses = rop.find_gadget({"pop rdi", "ret"});
        for (auto a : addresses)
            std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0')
                      << a << std::endl;
    } catch (const std::runtime_error &e) {
        std::cerr << e.what() << std::endl;
    }
}
