#include <ctf/rop.hpp>
#include <gtest/gtest.h>
#include <iostream>

using namespace ctf;

TEST(ROPTest, Output) {
    auto rop = ROP("../bin/vuln");
    try {
        auto gadgets = rop.gadgets();
        for (auto g : gadgets) {
            std::cout << "0x" << std::hex << g.ins[0].address;
            for (auto i : g.ins)
                std::cout << " " << i.assembly << ";";
            std::cout << std::endl;
        }

        auto addresses = rop.find_gadget({"pop rdi", "ret"});
        for (auto a : addresses)
            std::cout << "0x" << std::hex << a << std::endl;

        ASSERT_GT(gadgets.size(), 0);
        ASSERT_GT(addresses.size(), 0);
    } catch (const std::runtime_error &e) {
        std::cerr << e.what() << std::endl;
    }
}