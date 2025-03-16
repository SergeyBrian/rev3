#ifndef CORE_STATIC_STRINGS_HPP
#define CORE_STATIC_STRINGS_HPP
#include "../../target.hpp"

namespace core::static_analysis {
bool IsASCII(char c);
void FindStrings(Target &target);
}  // namespace core::static_analysis

#endif
