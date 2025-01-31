#include "target.hpp"

#include <filesystem>

#include "../config/config.hpp"

namespace core {
Function::Function(const LIEF::PE::ImportEntry &lief_info, const std::string &lib_name, const LIEF::PE::Binary *lief_bin)
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

    xrefs = lief_bin->xref(lief_info.hint_name_rva());

    this->lib_name = lib_name;
}

Target::Target(const std::string &filename) : filename(filename) {
    std::filesystem::path path(filename);
    name = path.stem().string();
}


void Target::DisassemblePOI() {
    for (const auto &[_, import] : imports) {
        for (const auto &func : import) {
            if (!func.is_interesting) continue;
            for (const auto &xref : func.xrefs) {
                disassembler.DisassembleNearby(lief_info.get(), xref);
            } 
        }
    }
}
}  // namespace core
