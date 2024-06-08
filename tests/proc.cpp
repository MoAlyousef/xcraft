#include <ctf/tube.hpp>
#include <ctf/utils.hpp>
#include <gtest/gtest.h>

using namespace ctf;

TEST(ProcesTest, Output) {
    auto process = Process("bash");
    process.write("echo Hello from bash\n");
    auto readln = process.readln();
    ASSERT_EQ(readln, "Hello from bash");
    process.writeln("exit");
    auto exit_status = process.exit_status();
}