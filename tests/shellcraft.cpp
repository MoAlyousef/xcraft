#include <ctf/enums.hpp>
#include <ctf/shellcraft.hpp>
#include <ctf/utils.hpp>
#include <gtest/gtest.h>

using namespace ctf;

TEST(Shellcraft, Output) {
    auto shellcode = linux_sh_x64();
    auto disasm    = disassemble(shellcode, Architecture::X86_64);
    auto as        = assemble(disasm.c_str(), Architecture::X86_64);
    ASSERT_EQ(shellcode, as.data());

    auto nop = assemble("nop");
    ASSERT_EQ(nop.size(), 1);
    ASSERT_EQ(nop[0], '\x90');
}