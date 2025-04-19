#pragma once

#include "binary.hpp"

namespace xcft {

class PE : public Binary {
    struct Impl;
    std::shared_ptr<Impl> pimpl;

  public:
    explicit PE(const fs::path &path);

    [[nodiscard]] bool statically_linked() const override;
    [[nodiscard]] address_map &iat() const;
    [[nodiscard]] address_map &ilt() const;
    size_t set_address(size_t addr) override;
};
} // namespace xcft
