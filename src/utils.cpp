#include <algorithm>
#include <cstdio>
#include <ctf/utils.hpp>
#include <fmt/format.h>
#include <numeric>
#include <span>
#include <string_view>
#include <vector>

template <typename T, size_t N, size_t... Indices>
constexpr std::array<T, N>
span_to_array_helper(std::span<T, N> span, std::index_sequence<Indices...>) {
    return {span[Indices]...};
}

template <typename T, size_t N>
constexpr std::array<T, N> span_to_array(std::span<T, N> span) {
    return span_to_array_helper(span, std::make_index_sequence<N>());
}

namespace ctf {

template <class T, Endian E>
    requires(std::is_integral_v<T>)
std::string p(T val) {
    std::string ret(reinterpret_cast<const char *>(&val), sizeof(T));
    if (E == Endian::Big)
        std::reverse(ret.begin(), ret.end());
    return ret;
}

template <class T, Endian E>
    requires(std::is_integral_v<T>)
T up(std::string_view a) {
    std::string v(a.begin(), a.end());
    for (size_t i = v.size(); i < sizeof(T); i++)
        v.push_back(0);
    if (E == Endian::Big) {
        std::reverse(v.begin(), v.end());
    }
    return *reinterpret_cast<T *>(v.data());
}

template std::string p<uint32_t, Endian::Little>(const uint32_t);

template std::string p<uint64_t, Endian::Little>(const uint64_t);

template std::string p<uint32_t, Endian::Big>(const uint32_t);

template std::string p<uint64_t, Endian::Big>(const uint64_t);

template std::string p<int32_t, Endian::Little>(const int32_t);

template std::string p<int64_t, Endian::Little>(const int64_t);

template std::string p<int32_t, Endian::Big>(const int32_t);

template std::string p<int64_t, Endian::Big>(const int64_t);

template uint32_t up<uint32_t, Endian::Little>(std::string_view a);

template uint64_t up<uint64_t, Endian::Little>(std::string_view a);

template uint32_t up<uint32_t, Endian::Big>(std::string_view a);

template uint64_t up<uint64_t, Endian::Big>(std::string_view a);

template int32_t up<int32_t, Endian::Little>(std::string_view a);

template int64_t up<int64_t, Endian::Little>(std::string_view a);

template int32_t up<int32_t, Endian::Big>(std::string_view a);

template int64_t up<int64_t, Endian::Big>(std::string_view a);

void db(
    size_t t,
    size_t p,
    std::vector<size_t> &a,
    std::vector<size_t> &sequence,
    size_t n,
    size_t k,
    std::span<size_t> alphabet
) {
    if (t > n) {
        if (n % p == 0) {
            for (size_t j = 1; j <= p; ++j) {
                sequence.push_back(alphabet[a[j]]);
            }
        }
    } else {
        a[t] = a[t - p];
        db(t + 1, p, a, sequence, n, k, alphabet);
        for (size_t j = a[t - p] + 1; j < k; ++j) {
            a[t] = j;
            db(t + 1, t, a, sequence, n, k, alphabet);
        }
    }
}

std::vector<size_t> cyclic_impl(std::span<size_t> alphabet, size_t n) {
    size_t k = alphabet.size();
    std::vector<size_t> a(k * n, 0);
    std::vector<size_t> sequence;

    db(1, 1, a, sequence, n, k, alphabet);
    return sequence;
}

std::string cyclic_alphabet_impl() noexcept {
    constexpr int alphabet = 26;
    std::array<size_t, alphabet> v{};
    std::iota(v.begin(), v.end(), 0);
    auto cyclicimpl = cyclic_impl(v, 4);
    std::string z;
    z.reserve(cyclicimpl.size());
    for (auto elem : cyclicimpl) {
        // NOLINTBEGIN
        z.push_back(elem + 'a');
        // NOLINTEND
    }
    return z;
}

const std::string CYCLIC = cyclic_alphabet_impl();

std::string cyclic(size_t len) {
    return {CYCLIC.begin(), CYCLIC.begin() + (long)len};
}

template <class T>
ptrdiff_t cyclic_find(T seq) {
    std::string s;
    if constexpr (std::is_integral_v<T>)
        s = p<T>(seq);
    else
        s = seq;
    const auto &c = CYCLIC;
    auto it       = std::search(c.begin(), c.end(), s.begin(), s.end());
    return std::distance(c.begin(), it);
}

template ptrdiff_t cyclic_find<uint32_t>(uint32_t seq);

template ptrdiff_t cyclic_find<uint64_t>(uint64_t seq);

template ptrdiff_t cyclic_find<int>(int seq);

template ptrdiff_t cyclic_find<long>(long seq);

template ptrdiff_t cyclic_find<const char *>(const char *seq);

void hex_print(std::string_view a) {
    for (auto i : a)
        fmt::print("\\x{:x}", i);
}

void hex_println(std::string_view a) {
    hex_print(a);
    fmt::println("");
}
} // namespace ctf
