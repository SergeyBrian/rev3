#include "parser.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <LIEF/LIEF.hpp>

#include "../../../utils/logger.hpp"

namespace core::static_analysis::parser {
Err ParseBinary(Target &target) {
    Err err{};
    logger::Debug("Running LIEF parser on target '%s'", target.name.c_str());
    auto result = LIEF::Parser::parse(target.filename);
    if (!result) {
        logger::Error("Parsing error");
        return Err::ParsingError;
    }

    logger::Okay("Parsing done");

    std::vector<std::string> libs = result->imported_libraries();
    auto imports = result->imported_functions();
    logger::Debug("Mapping %d imported symbols", imports.size());
    for (const auto &func : imports) {
        bool found = false;
        for (const auto &lib : libs) {
            HMODULE mod = LoadLibrary(lib.c_str());
            if (!mod) {
                logger::Warn("Failed to load %s. Skipping", lib.c_str());
                continue;
            }
            FARPROC func_addr = GetProcAddress(mod, func.name().c_str());
            FreeLibrary(mod);
            if (func_addr) {
                target.imports[lib].emplace_back(func, lib, result.get());
                found = true;
                break;
            }
        }
        if (!found) {
            logger::Warn("Symbol %s not found", func.name().c_str());
        }
    }


    target.lief_info = std::move(result);

    return err;
}
}  // namespace core::static_analysis::parser
