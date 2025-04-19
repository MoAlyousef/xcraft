#include <gtest/gtest.h>
#include <iostream>
#include <xcraft/elf.hpp>

using namespace xcft;

TEST(ELFTest, Output) {
    ELF e("../bin/vuln");
    std::cout << "------------------------" << std::endl;
    puts("SYM");
    for (auto elem : e.symbols()) {
        printf("%s 0x%016lx\n", elem.first.c_str(), elem.second);
    }
    ASSERT_GT(e.symbols().size(), 0);
    puts("PLT");
    for (auto elem : e.plt()) {
        printf("%s 0x%016lx\n", elem.first.c_str(), elem.second);
    }
    ASSERT_GT(e.plt().size(), 0);
    puts("GOT");
    for (auto elem : e.got()) {
        printf("%s 0x%016lx\n", elem.first.c_str(), elem.second);
    }
    ASSERT_GT(e.got().size(), 0);
}