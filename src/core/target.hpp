#ifndef CORE_STATIC_FILE_HPP
#define CORE_STATIC_FILE_HPP

#include <string>

#include <LIEF/LIEF.hpp>

#include "../utils/alias.hpp"

#include "static/disas/disassembler.hpp"

namespace core {
enum class InterestType { Source, Sink, Masking, Count };

inline const char *InterestTypeName[static_cast<int>(InterestType::Count)] = {
    "Source / Trigger",
    "Sink",
    "Masking",
};

struct InterestingFunction {
    std::string name;
    std::string lib_name;
    InterestType interest_type;
    std::string category;
};

struct Function {
    LIEF::PE::ImportEntry lief_info;
    std::string lib_name;
    InterestType interest_type{};
    std::string category{};
    bool is_interesting = false;
    std::vector<u64> xrefs;

    Function(const LIEF::PE::ImportEntry &lief_info, const std::string &lib_name, const LIEF::PE::Binary *lief_bin);
};

struct Target {
    std::string filename;
    std::string name;
    std::unique_ptr<LIEF::PE::Binary> lief_info{};
    std::map<std::string, std::vector<Function>> imports;
    static_analysis::disassembler::Disassembler disassembler;

    Target(const std::string &filename);
    void DisassemblePOI();
};
}  // namespace core

#endif
