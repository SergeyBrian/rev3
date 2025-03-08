#ifndef CORE_STATIC_CALLS_H
#define CORE_STATIC_CALLS_H

#include "../../target.hpp"

namespace core::static_analysis {

void FindReferences(Target &target);
void FindCallsArgs(Target &target);
}  // namespace core::static_analysis

#endif
