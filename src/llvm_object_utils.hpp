#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <optional>
#include <filesystem>
#include <xcraft/enums.hpp>

namespace fs = std::filesystem;

namespace xcft {

// Forward declarations to avoid including LLVM headers in public interface
namespace llvm_detail {
class ObjectFileWrapper;
}

using address_map = std::unordered_map<std::string, uint64_t>;

enum class BinaryFormat {
    ELF,
    PE,
    MachO,
    Unknown
};

enum class LLVMEndianness {
    Little,
    Big
};

struct BinaryInfo {
    BinaryFormat format;
    Architecture arch;
    LLVMEndianness endianness;
    bool is_64bit;
    uint64_t entry_point;
    uint64_t base_address;
};

struct Section {
    std::string name;
    uint64_t address;
    uint64_t size;
    std::vector<uint8_t> data;
    bool executable;
    bool writable;
    bool readable;
};

class LLVMObjectFile {
private:
    std::unique_ptr<llvm_detail::ObjectFileWrapper> impl_;
    
public:
    explicit LLVMObjectFile(const fs::path& path);
    ~LLVMObjectFile();
    
    // Non-copyable but movable
    LLVMObjectFile(const LLVMObjectFile&) = delete;
    LLVMObjectFile& operator=(const LLVMObjectFile&) = delete;
    LLVMObjectFile(LLVMObjectFile&&) noexcept;
    LLVMObjectFile& operator=(LLVMObjectFile&&) noexcept;
    
    BinaryInfo get_info() const;
    address_map get_symbols() const;
    address_map extract_strings(size_t min_length = 4) const;
    std::vector<Section> get_sections() const;
    std::vector<Section> get_executable_sections() const;
    
    // Format-specific methods
    address_map get_plt() const;        // ELF only
    address_map get_got() const;        // ELF only  
    address_map get_iat() const;        // PE only
    address_map get_symbol_stubs() const; // MachO only
    
    // ELF-specific methods
    bool is_dynamically_linked() const;
    bool has_relro() const;
    bool has_full_relro() const;
    bool has_bind_now() const;
    
    bool has_stack_canaries() const;
    bool is_position_independent() const;
    bool has_executable_stack() const;
};

} // namespace xcft