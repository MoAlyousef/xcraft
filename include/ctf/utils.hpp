#pragma once

#include <cstddef>
#include <ctf/enums.hpp>
#include <string>
#include <type_traits>

namespace ctf {

template <typename T = char, typename Container, typename... Containers>
constexpr void append_ranges(
    std::string &v, const Container &first, const Containers &...rest
) {
    for (const auto &elem : first) {
            v.push_back(elem);
    }
    if constexpr (sizeof...(rest) > 0) {
        append_ranges(v, rest...);
    }
}

template <typename T = char, typename Container, typename... Containers>
std::string from_ranges(const Container &first, const Containers &...rest) {
    std::string v;
    append_ranges(v, first, rest...);
    return v;
}

template <class T, Endian E = Endian::Little>
    requires(std::is_integral_v<T>)
std::string p(const T val);

template <class T, Endian E = Endian::Little>
    requires(std::is_integral_v<T>)
T up(std::string_view a);

std::string str(std::string_view b);

std::string cyclic(size_t len);

template <class T>
ptrdiff_t cyclic_find(T seq);

void hex_print(std::string_view a);

void hex_println(std::string_view a);
} // namespace ctf
