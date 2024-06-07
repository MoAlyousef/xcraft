#pragma once

#include "binary.hpp"

namespace ctf {

class MachO : public Binary {
    struct Impl;
    std::shared_ptr<Impl> pimpl;

  public:
    explicit MachO(fs::path path);
    [[nodiscard]] bool statically_linked() const override;
    [[nodiscard]] address_map &stubs() const;
    [[nodiscard]] address_map &iat() const;
    size_t set_address(size_t addr) override;
};
} // namespace ctf
