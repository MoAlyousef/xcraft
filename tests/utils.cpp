#include <ctf/utils.hpp>
#include <gtest/gtest.h>

using namespace ctf;
using namespace std::literals;

TEST(UtilsTest, BasicAssertions) {
    auto x = from_ranges("hello "sv, "world"sv);
    std::cout << x << std::endl;
    auto y =
        from_ranges(cyclic(20), p<uint32_t>(0xdeadbeef), "\xbe\xba\xfe\xca");
    const char *val =
        "\x61\x61\x61\x61\x62\x61\x61\x61\x63\x61\x61\x61\x64\x61"
        "\x61\x61\x65\x61\x61\x61\xef\xbe\xad\xde\xbe\xba\xfe\xca";
    x.shrink_to_fit();
    ASSERT_EQ(y, val);

    // check print functions
    std::cout << y << std::endl;
    hex_println(y);

    auto be = p<uint32_t, Endian::Big>(0xdeadbeef);
    ASSERT_EQ(be, "\xde\xad\xbe\xef");
    auto ube = up<uint32_t, Endian::Big>(be);
    ASSERT_EQ(ube, 0xdeadbeef);
    ASSERT_EQ(p<uint32_t>(0xcafebabe), "\xbe\xba\xfe\xca");
    auto aa = "\xbe\xba\xfe\xca";
    ASSERT_EQ(up<uint32_t>("\xbe\xba\xfe\xca"), 0xcafebabe);
    ASSERT_EQ(cyclic(20), "aaaabaaacaaadaaaeaaa");
    ASSERT_EQ(cyclic_find<uint32_t>(0x61616163), 8);
    ASSERT_EQ(cyclic_find("caaa"), 8);
}