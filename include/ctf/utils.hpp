#pragma once

#include <cstddef>
#include <ctf/enums.hpp>
#include <string>
#include <type_traits>

namespace ctf {

template <typename T = char, typename Container, typename... Containers>
constexpr void append_ranges(
    std::string &v, Container &&first, Containers &&...rest
) {
    v += std::forward<Container>(first);
    if constexpr (sizeof...(rest) > 0) {
        append_ranges(v, std::forward<Containers>(rest)...);
    }
}

template <typename T = char, typename Container, typename... Containers>
std::string from_ranges(Container &&first, Containers &&...rest) {
    std::string v;
    append_ranges(
        v, std::forward<Container>(first), std::forward<Containers>(rest)...
    );
    return v;
}

template <class T, Endian E = Endian::Little>
    requires(std::is_integral_v<T>)
std::string p(const T val);

template <class T, Endian E = Endian::Little>
    requires(std::is_integral_v<T>)
T up(std::string_view a);

std::string cyclic(size_t len);

template <class T>
ptrdiff_t cyclic_find(T seq);

void hex_print(std::string_view a);

void hex_println(std::string_view a);
} // namespace ctf
