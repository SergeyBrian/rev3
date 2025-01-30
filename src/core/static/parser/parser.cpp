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
    auto result = LIEF::PE::Parser::parse(target.filename);
    if (!result) {
        logger::Error("Parsing error");
        return Err::ParsingError;
    }

    logger::Okay("Parsing done");

    auto libs = result->imports();
    for (const auto &lib : libs) {
        for (const auto &entry : lib.entries()) {
            target.imports[lib.name()].emplace_back(entry, lib.name(), result.get());
        }
    }


    target.lief_info = std::move(result);

    return err;
}
}  // namespace core::static_analysis::parser
