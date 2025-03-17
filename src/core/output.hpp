#ifndef CORE_OUTPUT_HPP
#define CORE_OUTPUT_HPP

#include "target.hpp"
namespace core::output {
void PrintImports(const Target &target);
void PrintFunctions(const Target *target, Tag tag);
void PrintRefs(const Target *target, u64 addr);
}  // namespace core::output

#endif
