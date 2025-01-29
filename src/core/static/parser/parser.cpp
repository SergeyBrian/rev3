#include "parser.hpp"

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
    target.lief_info = std::move(result);

    return err;
}
}
