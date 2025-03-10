#ifndef CORE_DYNAMIC_SOLVER_HPP
#define CORE_DYNAMIC_SOLVER_HPP

#include "../../target.hpp"

namespace core::dynamic::solver {
void CleanUpTrace(const Target *target,
                  std::vector<static_analysis::CFGNode *> &path);
[[nodiscard]] std::string Solve(
    const Target *target, const std::vector<static_analysis::CFGNode *> &path);
}  // namespace core::dynamic::solver

#endif
