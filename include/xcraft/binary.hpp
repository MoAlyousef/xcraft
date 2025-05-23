#pragma once

#include "enums.hpp"
#include <filesystem>
#include <initializer_list>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace fs      = std::filesystem;
using address_map = std::unordered_map<std::string, uint64_t>;

namespace xcft {
class Binary {
    struct Impl;
    std::shared_ptr<Impl> pimpl;

  protected:
    Binary(const Binary &)                = default;
    Binary &operator=(const Binary &)     = default;
    Binary(Binary &&) noexcept            = default;
    Binary &operator=(Binary &&) noexcept = default;
    void *bin();

  public:
    explicit Binary(const fs::path &);
    virtual ~Binary() = default;

    [[nodiscard]] fs::path path() const;
    [[nodiscard]] Bits bits() const;
    [[nodiscard]] address_map &symbols() const;
    [[nodiscard]] address_map &strings() const;
    std::vector<size_t> search(std::initializer_list<std::string_view> seq);
    [[nodiscard]] Endian endianness() const;
    [[nodiscard]] Architecture arch() const;
    [[nodiscard]] bool executable_stack() const;
    [[nodiscard]] bool position_independent() const;
    [[nodiscard]] bool stack_canaries() const;
    [[nodiscard]] size_t address() const;
    virtual size_t set_address(size_t addr);
    [[nodiscard]] virtual bool statically_linked() const = 0;
};
} // namespace xcft
