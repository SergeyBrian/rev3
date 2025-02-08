#ifndef CORE_STATIC_PARSER_HPP
#define CORE_STATIC_PARSER_HPP

#include "../../../utils/errors.hpp"

#include "../../target.hpp"

namespace core::static_analysis::parser {
Err ParseBinary(Target &target);
std::vector<u64> FindImportsXrefs(LIEF::PE::Binary *bin, u64 addr, Err *err);
}  // namespace core::static_analysis::parser

#endif
