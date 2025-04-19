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

extern template std::string p<uint32_t, Endian::Little>(const uint32_t);
extern template std::string p<uint64_t, Endian::Little>(const uint64_t);
extern template std::string p<uint32_t, Endian::Big>(const uint32_t);
extern template std::string p<uint64_t, Endian::Big>(const uint64_t);
extern template std::string p<int32_t, Endian::Little>(const int32_t);
extern template std::string p<int64_t, Endian::Little>(const int64_t);
extern template std::string p<int32_t, Endian::Big>(const int32_t);
extern template std::string p<int64_t, Endian::Big>(const int64_t);
extern template uint32_t up<uint32_t, Endian::Little>(std::string_view a);
extern template uint64_t up<uint64_t, Endian::Little>(std::string_view a);
extern template uint32_t up<uint32_t, Endian::Big>(std::string_view a);
extern template uint64_t up<uint64_t, Endian::Big>(std::string_view a);
extern template int32_t up<int32_t, Endian::Little>(std::string_view a);
extern template int64_t up<int64_t, Endian::Little>(std::string_view a);
extern template int32_t up<int32_t, Endian::Big>(std::string_view a);
extern template int64_t up<int64_t, Endian::Big>(std::string_view a);
extern template ptrdiff_t cyclic_find<uint32_t>(uint32_t seq);
extern template ptrdiff_t cyclic_find<uint64_t>(uint64_t seq);
extern template ptrdiff_t cyclic_find<int>(int seq);
extern template ptrdiff_t cyclic_find<long>(long seq);
extern template ptrdiff_t cyclic_find<const char *>(const char *seq);
} // namespace ctf
