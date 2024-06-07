#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <ctf/enums.hpp>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace ctf {

template <typename T, typename Container, typename... Containers>
constexpr void append_ranges(
    std::vector<T> &v, const Container &first, const Containers &...rest
) {
    for (const auto &elem : first) {
        v.push_back(elem);
    }
    if constexpr (sizeof...(rest) > 0) {
        append_ranges(v, rest...);
    }
}

template <typename T, typename Container, typename... Containers>
constexpr std::vector<T> from_ranges(
    const Container &first, const Containers &...rest
) {
    std::vector<T> v;
    append_ranges(v, first, rest...);
    return v;
}

template <class T, Endian E = Endian::Little>
    requires(std::is_integral_v<T>)
std::array<unsigned char, sizeof(T)> p(const T val);

template <class T, Endian E = Endian::Little>
    requires(std::is_integral_v<T>)
T up(std::span<const unsigned char> a);

std::span<const unsigned char> operator""_b(const char8_t *str, size_t sz);

std::span<const unsigned char> operator""_b(const char *str, size_t sz);

std::string str(std::span<unsigned char> b);

std::vector<unsigned char> cyclic(size_t len);

template <class T>
    requires(std::is_integral_v<T>)
ptrdiff_t cyclic_find(T seq);

void println(std::span<const unsigned char> a);

void print(std::span<const unsigned char> a);

void hex_print(std::span<const unsigned char> a);

void hex_println(std::span<const unsigned char> a);
} // namespace ctf
