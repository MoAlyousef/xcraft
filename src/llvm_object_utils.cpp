#include "llvm_object_utils.hpp"

#include <llvm/Object/ObjectFile.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/MachO.h>
#include <llvm/Object/ELFTypes.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/ADT/StringRef.h>

#include <algorithm>
#include <stdexcept>
#include <fmt/format.h>

using namespace llvm;
using namespace llvm::object;

namespace xcft {
namespace llvm_detail {

class ObjectFileWrapper {
private:
    std::unique_ptr<MemoryBuffer> buffer_;
    std::unique_ptr<ObjectFile> obj_file_;

public:
    explicit ObjectFileWrapper(const fs::path& path) {
        auto buffer_or_err = MemoryBuffer::getFile(path.string());
        if (!buffer_or_err) {
            throw std::runtime_error(
                fmt::format("Failed to read file: {}", path.string())
            );
        }
        buffer_ = std::move(*buffer_or_err);
        
        auto obj_or_err = ObjectFile::createObjectFile(buffer_->getMemBufferRef());
        if (!obj_or_err) {
            throw std::runtime_error(
                fmt::format("Failed to parse object file: {}", path.string())
            );
        }
        obj_file_ = std::move(*obj_or_err);
    }
    
    ObjectFile* get() const { return obj_file_.get(); }
    
    template<typename T>
    T* get_as() const {
        return dyn_cast<T>(obj_file_.get());
    }
};

} // namespace llvm_detail

// Helper functions for conversion
BinaryFormat get_binary_format(const ObjectFile* obj) {
    if (isa<ELFObjectFileBase>(obj)) return BinaryFormat::ELF;
    if (isa<COFFObjectFile>(obj)) return BinaryFormat::PE;
    if (isa<MachOObjectFile>(obj)) return BinaryFormat::MachO;
    return BinaryFormat::Unknown;
}

Architecture get_architecture(const ObjectFile* obj) {
    auto arch = obj->getArch();
    switch (arch) {
        case Triple::x86: return Architecture::X86;
        case Triple::x86_64: return Architecture::X86_64;
        case Triple::arm: return Architecture::Arm;
        case Triple::aarch64: return Architecture::Aarch64;
        default: return Architecture::Other;
    }
}

LLVMEndianness get_endianness(const ObjectFile* obj) {
    return obj->isLittleEndian() ? LLVMEndianness::Little : LLVMEndianness::Big;
}

bool is_printable(unsigned char c) {
    return c >= 32 && c <= 126;
}

address_map extract_strings_from_data(
    const uint8_t* data, size_t size, uint64_t base_addr, size_t min_len
) {
    address_map result;
    const uint8_t* cur = data;
    const uint8_t* end = data + size;
    const uint8_t* start = nullptr;
    
    while (cur < end) {
        if (is_printable(*cur)) {
            if (!start) start = cur;
        } else {
            if (start && (cur - start) >= min_len) {
                std::string str(reinterpret_cast<const char*>(start), cur - start);
                result[str] = base_addr + (start - data);
            }
            start = nullptr;
        }
        ++cur;
    }
    
    if (start && (cur - start) >= min_len) {
        std::string str(reinterpret_cast<const char*>(start), cur - start);
        result[str] = base_addr + (start - data);
    }
    
    return result;
}

// Implementation of LLVMObjectFile
LLVMObjectFile::LLVMObjectFile(const fs::path& path) 
    : impl_(std::make_unique<llvm_detail::ObjectFileWrapper>(path)) {}

LLVMObjectFile::~LLVMObjectFile() = default;

LLVMObjectFile::LLVMObjectFile(LLVMObjectFile&&) noexcept = default;
LLVMObjectFile& LLVMObjectFile::operator=(LLVMObjectFile&&) noexcept = default;

BinaryInfo LLVMObjectFile::get_info() const {
    auto* obj = impl_->get();
    
    BinaryInfo info;
    info.format = get_binary_format(obj);
    info.arch = get_architecture(obj);
    info.endianness = get_endianness(obj);
    info.is_64bit = obj->is64Bit();
    info.entry_point = 0; // Will need format-specific implementation
    info.base_address = 0; // Will need format-specific implementation
    
    return info;
}

address_map LLVMObjectFile::get_symbols() const {
    address_map result;
    auto* obj = impl_->get();
    
    // First try regular symbol table
    for (const auto& symbol : obj->symbols()) {
        auto name_or_err = symbol.getName();
        if (!name_or_err) continue;
        
        auto addr_or_err = symbol.getAddress();
        if (!addr_or_err) continue;
        
        result[name_or_err->str()] = *addr_or_err;
    }
    
    // For shared libraries, also check dynamic symbol table
    if (auto* elf_obj = llvm::dyn_cast<llvm::object::ELFObjectFileBase>(obj)) {
        for (const auto& symbol : elf_obj->getDynamicSymbolIterators()) {
            auto name_or_err = symbol.getName();
            if (!name_or_err) continue;
            
            auto addr_or_err = symbol.getAddress();
            if (!addr_or_err) continue;
            
            // Only add if not already present (regular symbols take precedence)
            if (result.find(name_or_err->str()) == result.end()) {
                result[name_or_err->str()] = *addr_or_err;
            }
        }
    }
    
    return result;
}

address_map LLVMObjectFile::extract_strings(size_t min_length) const {
    address_map result;
    auto sections = get_sections();
    
    for (const auto& section : sections) {
        auto strings = extract_strings_from_data(
            section.data.data(), section.data.size(), section.address, min_length
        );
        result.merge(strings);
    }
    
    return result;
}

std::vector<Section> LLVMObjectFile::get_sections() const {
    std::vector<Section> result;
    auto* obj = impl_->get();
    
    for (const auto& sec : obj->sections()) {
        Section section;
        
        auto name_or_err = sec.getName();
        if (name_or_err) {
            section.name = name_or_err->str();
        }
        
        section.address = sec.getAddress();
        section.size = sec.getSize();
        section.executable = sec.isText();
        
        // Determine section permissions based on format and section name
        std::string sec_name = section.name;
        if (isa<ELFObjectFileBase>(obj)) {
            // ELF section permissions - common patterns
            section.writable = (sec_name.find(".data") != std::string::npos ||
                              sec_name.find(".bss") != std::string::npos ||
                              sec_name.find(".got") != std::string::npos ||
                              sec_name == ".dynamic");
            section.readable = true; // Most ELF sections are readable
        } else if (isa<COFFObjectFile>(obj)) {
            // PE section permissions - based on characteristics
            section.writable = (sec_name.find(".data") != std::string::npos ||
                              sec_name.find(".bss") != std::string::npos ||
                              sec_name.find(".idata") != std::string::npos);
            section.readable = true; // Most PE sections are readable
        } else {
            // Default fallback
            section.writable = !section.executable; // Code sections typically not writable
            section.readable = true;
        }
        
        // Get section contents
        auto contents_or_err = sec.getContents();
        if (contents_or_err) {
            auto contents = *contents_or_err;
            section.data.assign(contents.bytes_begin(), contents.bytes_end());
        }
        
        result.push_back(std::move(section));
    }
    
    return result;
}

std::vector<Section> LLVMObjectFile::get_executable_sections() const {
    auto sections = get_sections();
    std::vector<Section> result;
    
    std::copy_if(sections.begin(), sections.end(), std::back_inserter(result),
        [](const Section& s) { return s.executable; });
        
    return result;
}

address_map LLVMObjectFile::get_plt() const {
    address_map result;
    auto* elf = impl_->get_as<ELFObjectFileBase>();
    if (!elf) return result;
    
    // Find .plt section
    const SectionRef* plt_section = nullptr;
    for (const auto& sec : elf->sections()) {
        auto name_or_err = sec.getName();
        if (name_or_err && *name_or_err == ".plt") {
            plt_section = &sec;
            break;
        }
    }
    
    if (!plt_section) return result;
    
    uint64_t plt_base = plt_section->getAddress();
    uint64_t entry_size = elf->is64Bit() ? 16 : 16; // PLT entry size is typically 16 bytes
    
    // Map PLT entries by iterating over relocations
    size_t index = 0;
    for (const auto& section : elf->sections()) {
        auto name_or_err = section.getName();
        if (!name_or_err) continue;
        
        std::string name = name_or_err->str();
        if (name == ".rela.plt" || name == ".rel.plt") {
            for (const auto& reloc : section.relocations()) {
                auto symbol_iter = reloc.getSymbol();
                if (symbol_iter == elf->symbol_end()) continue;
                
                auto sym_name_or_err = symbol_iter->getName();
                if (!sym_name_or_err) continue;
                
                std::string sym_name = sym_name_or_err->str();
                if (!sym_name.empty()) {
                    // Skip first PLT entry (PLT0)
                    uint64_t plt_address = plt_base + entry_size * (index + 1);
                    result[sym_name] = plt_address;
                }
                index++;
            }
            break;
        }
    }
    
    return result;
}

address_map LLVMObjectFile::get_got() const {
    address_map result;
    auto* elf = impl_->get_as<ELFObjectFileBase>();
    if (!elf) return result;
    
    // Map GOT entries by iterating over relocations
    for (const auto& section : elf->sections()) {
        auto name_or_err = section.getName();
        if (!name_or_err) continue;
        
        std::string name = name_or_err->str();
        if (name == ".rela.plt" || name == ".rel.plt" || 
            name == ".rela.dyn" || name == ".rel.dyn") {
            for (const auto& reloc : section.relocations()) {
                auto symbol_iter = reloc.getSymbol();
                if (symbol_iter == elf->symbol_end()) continue;
                
                auto sym_name_or_err = symbol_iter->getName();
                if (!sym_name_or_err) continue;
                
                std::string sym_name = sym_name_or_err->str();
                if (!sym_name.empty()) {
                    // The relocation address is the GOT entry address
                    result[sym_name] = reloc.getOffset();
                }
            }
        }
    }
    
    return result;
}

address_map LLVMObjectFile::get_iat() const {
    address_map result;
    auto* pe = impl_->get_as<COFFObjectFile>();
    if (!pe) return result;
    
    // Parse import table for IAT entries
    for (const auto& import_entry : pe->import_directories()) {
        StringRef dll_name;
        if (import_entry.getName(dll_name)) continue;
        
        uint32_t import_address_table_rva = 0;
        if (import_entry.getImportAddressTableRVA(import_address_table_rva)) continue;
        
        if (import_address_table_rva != 0) {
            // Use a simplified approach - map DLL name to IAT base
            result[dll_name.str() + "_iat"] = import_address_table_rva;
        }
    }
    
    return result;
}

address_map LLVMObjectFile::get_symbol_stubs() const {
    address_map result;
    auto* macho = impl_->get_as<MachOObjectFile>();
    if (!macho) return result;
    
    // Parse external symbols from Mach-O symbol table
    for (const auto& symbol : macho->symbols()) {
        auto name_or_err = symbol.getName();
        if (!name_or_err) continue;
        
        auto flags_or_err = symbol.getFlags();
        if (flags_or_err && (*flags_or_err & SymbolRef::SF_Undefined)) {
            // This is an external symbol (undefined in this binary)
            auto addr_or_err = symbol.getAddress();
            if (addr_or_err && *addr_or_err != 0) {
                std::string name = name_or_err->str();
                if (!name.empty()) {
                    result[name] = *addr_or_err;
                }
            }
        }
    }
    
    return result;
}

bool LLVMObjectFile::has_stack_canaries() const {
    auto symbols = get_symbols();
    return symbols.find("__stack_chk_fail") != symbols.end() ||
           symbols.find("__security_cookie") != symbols.end();
}

bool LLVMObjectFile::is_position_independent() const {
    auto* obj = impl_->get();
    
    if (auto* elf = impl_->get_as<ELFObjectFileBase>()) {
        // For ELF, check if it's ET_DYN (shared object/PIE) by examining symbols/sections
        // ET_DYN files typically have a base address of 0
        for (const auto& symbol : elf->symbols()) {
            auto addr_or_err = symbol.getAddress();
            if (addr_or_err && *addr_or_err > 0x400000) {
                return false; // Typical static binary base address
            }
        }
        return true; // Likely PIE/shared object
    } else if (auto* pe = impl_->get_as<COFFObjectFile>()) {
        // For PE, check DYNAMIC_BASE characteristic
        auto characteristics = pe->getCOFFHeader()->Characteristics;
        return (characteristics & COFF::IMAGE_FILE_RELOCS_STRIPPED) == 0;
    } else if (auto* macho = impl_->get_as<MachOObjectFile>()) {
        // For Mach-O, check MH_PIE flag in header
        auto header_flags = macho->getHeader().flags;
        return (header_flags & MachO::MH_PIE) != 0;
    }
    
    return false; // Default to non-PIE if format unknown
}

bool LLVMObjectFile::has_executable_stack() const {
    auto* elf = impl_->get_as<ELFObjectFileBase>();
    if (!elf) return false;
    
    // Check for .note.GNU-stack section as an indicator
    for (const auto& section : elf->sections()) {
        auto name_or_err = section.getName();
        if (name_or_err && *name_or_err == ".note.GNU-stack") {
            // If the section exists, stack is non-executable
            return false;
        }
    }
    
    // If no GNU-stack note found, assume executable (unsafe)
    return true;
}

bool LLVMObjectFile::is_dynamically_linked() const {
    auto* elf = impl_->get_as<ELFObjectFileBase>();
    if (!elf) return false;
    
    // Check for dynamic sections/symbols
    for (const auto& sec : elf->sections()) {
        auto name_or_err = sec.getName();
        if (name_or_err) {
            std::string name = name_or_err->str();
            if (name == ".dynamic" || name == ".dynsym" || name == ".dynstr") {
                return true;
            }
        }
    }
    return false;
}

bool LLVMObjectFile::has_relro() const {
    auto* elf = impl_->get_as<ELFObjectFileBase>();
    if (!elf) return false;
    
    // Check for .got.plt section which indicates RELRO is possible
    // This is a simplified check - real RELRO detection needs program headers
    for (const auto& section : elf->sections()) {
        auto name_or_err = section.getName();
        if (name_or_err && *name_or_err == ".got.plt") {
            return true;
        }
    }
    
    return false;
}

bool LLVMObjectFile::has_full_relro() const {
    if (!has_relro()) return false;
    return has_bind_now();
}

bool LLVMObjectFile::has_bind_now() const {
    auto* elf = impl_->get_as<ELFObjectFileBase>();
    if (!elf) return false;
    
    // Check for BIND_NOW flag by examining the dynamic section
    for (const auto& section : elf->sections()) {
        auto name_or_err = section.getName();
        if (name_or_err && *name_or_err == ".dynamic") {
            // Parse dynamic section entries
            auto contents_or_err = section.getContents();
            if (!contents_or_err) continue;
            
            auto contents = *contents_or_err;
            const uint8_t* data = contents.bytes_begin();
            size_t size = contents.size();
            
            // Simple check for DT_FLAGS with DF_BIND_NOW bit
            // This is architecture-dependent, but we'll do a basic search
            for (size_t i = 0; i + 16 <= size; i += 16) {
                uint64_t tag = *reinterpret_cast<const uint64_t*>(data + i);
                uint64_t val = *reinterpret_cast<const uint64_t*>(data + i + 8);
                
                // DT_BIND_NOW = 24
                if (tag == 24) {
                    return true;
                }
                // DT_FLAGS = 30, check for DF_BIND_NOW (0x8)
                if (tag == 30 && (val & 0x8)) {
                    return true;
                }
                // DT_FLAGS_1 = 0x6ffffffb, check for DF_1_NOW (0x1)
                if (tag == 0x6ffffffb && (val & 0x1)) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

} // namespace xcft