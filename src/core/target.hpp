#ifndef CORE_STATIC_FILE_HPP
#define CORE_STATIC_FILE_HPP

#include <string>

#include <LIEF/LIEF.hpp>

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
    LIEF::Function lief_info;
    std::string lib_name;
    InterestType interest_type{};
    std::string category{};
    bool is_interesting = false;

    Function(LIEF::Function lief_info, const std::string &lib_name);
};

struct Target {
    std::string filename;
    std::string name;
    std::unique_ptr<LIEF::Binary> lief_info{};
    std::map<std::string, std::vector<Function>> imports;

    Target(const std::string &filename);
};
}  // namespace core

#endif
