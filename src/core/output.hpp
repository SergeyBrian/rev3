#ifndef CORE_OUTPUT_HPP
#define CORE_OUTPUT_HPP

#include "target.hpp"
namespace core::output {
void PrintImports(const Target &target);
void PrintFunctions(const Target *target);
}  // namespace core::output

#endif
