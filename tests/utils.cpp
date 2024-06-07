#include <ctf/utils.hpp>
#include <gtest/gtest.h>
#include <vector>

using namespace ctf;

TEST(UtilsTest, BasicAssertions) {
    auto x = from_ranges<uint8_t>(
        cyclic(20), p<uint32_t>(0xdeadbeef), u8"\xbe\xba\xfe\xca"_b
    );
    uint8_t val[] = "\x61\x61\x61\x61\x62\x61\x61\x61\x63\x61\x61\x61\x64\x61"
                    "\x61\x61\x65\x61\x61\x61\xef\xbe\xad\xde\xbe\xba\xfe\xca";
    ASSERT_EQ(memcmp(x.data(), val, x.size()), 0);

    // check print functions
    println(x);
    hex_println(x);

    auto be = p<uint32_t, Endian::Big>(0xdeadbeef);
    ASSERT_EQ(memcmp(be.data(), "\xde\xad\xbe\xef", 4), 0);
    auto ube = up<uint32_t, Endian::Big>(be);
    ASSERT_EQ(ube, 0xdeadbeef);
    ASSERT_EQ(memcmp(p<uint32_t>(0xcafebabe).data(), "\xbe\xba\xfe\xca", 4), 0);
    auto aa = u8"\xbe\xba\xfe\xca"_b;
    ASSERT_EQ(up<uint32_t>("\xbe\xba\xfe\xca"_b), 0xcafebabe);
    ASSERT_EQ(memcmp(cyclic(20).data(), "aaaabaaacaaadaaaeaaa", 20), 0);
    ASSERT_EQ(cyclic_find<uint32_t>(0x61616163), 8);
}