#pragma once

#include "binary.hpp"
#include "enums.hpp"

namespace ctf {

class ELF : public Binary {
    struct Impl;
    std::shared_ptr<Impl> pimpl;

  public:
    explicit ELF(fs::path path);
    [[nodiscard]] RelroType relro() const;
    [[nodiscard]] bool statically_linked() const override;
    [[nodiscard]] address_map &got() const;
    [[nodiscard]] address_map &plt() const;
    size_t set_address(size_t addr) override;
};
} // namespace ctf
