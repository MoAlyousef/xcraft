#pragma once

#include <bit>
#include "enums.hpp"
#include <filesystem>
#include <initializer_list>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace fs      = std::filesystem;
using address_map = std::unordered_map<std::string, size_t>;

namespace ctf {
class Binary {
    struct Impl;
    std::shared_ptr<Impl> pimpl;

  protected:
    void *bin();

  public:
    Binary(fs::path);
    [[nodiscard]] fs::path path() const;
    [[nodiscard]] address_map &symbols() const;
    [[nodiscard]] address_map &strings() const;
    std::vector<size_t> search(std::initializer_list<std::string_view> seq);
    [[nodiscard]] std::endian endianness() const;
    [[nodiscard]] Architecture arch() const;
    [[nodiscard]] bool executable_stack() const;
    [[nodiscard]] bool position_independent() const;
    [[nodiscard]] bool stack_canaries() const;
    [[nodiscard]] size_t address() const;
    virtual size_t set_address(size_t addr);
    [[nodiscard]] virtual bool statically_linked() const = 0;
    virtual ~Binary();
};
} // namespace ctf
