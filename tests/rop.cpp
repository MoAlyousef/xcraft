#include <gtest/gtest.h>
#include <iostream>
#include <xcraft/rop.hpp>

using namespace xcft;

TEST(ROPTest, Output) {
    auto rop = ROP("../bin/vuln");
    try {
        auto gadgets = rop.gadgets();
        for (auto g : gadgets) {
            std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << g.ins[0].address;
            for (auto i : g.ins)
                std::cout << " " << i.assembly << ";";
            std::cout << std::endl;
        }

        auto addresses = rop.find_gadget({"pop rdi", "ret"});
        for (auto a : addresses)
            std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << a << std::endl;

        ASSERT_GT(gadgets.size(), 0);
        ASSERT_GT(addresses.size(), 0);
    } catch (const std::runtime_error &e) {
        std::cerr << e.what() << std::endl;
    }
}