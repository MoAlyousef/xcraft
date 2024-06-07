#pragma once

#include <filesystem>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace ctf {

struct Instruction {
    uint64_t address;
    std::string bytes;
    std::string assembly;
};

struct Gadget {
    std::vector<Instruction> ins;
};

class ROP {
    fs::path path_;
    std::vector<Gadget> gadgets_ = {};

  public:
    explicit ROP(fs::path p);
    [[nodiscard]] const std::vector<Gadget> &gadgets();
    std::vector<size_t> find_gadget(std::initializer_list<std::string_view> seq
    );
};
} // namespace ctf
