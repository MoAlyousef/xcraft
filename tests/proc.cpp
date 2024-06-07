#include <ctf/tube.hpp>
#include <ctf/utils.hpp>
#include <gtest/gtest.h>

using namespace ctf;

TEST(ProcesTest, Output) {
    auto process = Process("bash");
    process.write("echo Hello from bash\n"_b);
    auto readln = process.readln();
    ASSERT_EQ(memcmp(readln.data(), "Hello from bash", readln.size()), 0);
    process.writeln("exit"_b);
    auto exit_status = process.exit_status();
}