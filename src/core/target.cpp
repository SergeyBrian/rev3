#include "target.hpp"

#include <filesystem>

#include "../config/config.hpp"

namespace core {
Function::Function(LIEF::Function lief_info, const std::string &lib_name)
    : lief_info(lief_info) {
    auto interests = config::Get().static_analysis.interesting_functions;
    std::string lower_name = lief_info.name();
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                   ::tolower);

    std::string lower_lib_name = lib_name;
    std::transform(lower_lib_name.begin(), lower_lib_name.end(),
                   lower_lib_name.begin(), ::tolower);

    for (const auto &interest : interests) {
        if (interest.lib_name == lower_lib_name &&
            interest.name == lower_name) {
            category = interest.category;
            interest_type = interest.interest_type;
            is_interesting = true;
            break;
        }
    }

    this->lib_name = lib_name;
}

Target::Target(const std::string &filename) : filename(filename) {
    std::filesystem::path path(filename);
    name = path.stem().string();
}
}  // namespace core
