#ifndef CORE_DYNAMIC_SOLVER_HPP
#define CORE_DYNAMIC_SOLVER_HPP

#include "../../target.hpp"

namespace core::dynamic::solver {
struct Choice {
    // Next address
    u64 addr1;
    // Branch address
    u64 addr2;
    bool taken;
};

void CleanUpTrace(const Target *target,
                  std::vector<static_analysis::CFGNode *> &path);
[[nodiscard]] std::string Solve(
    const Target *target, const std::vector<static_analysis::CFGNode *> &path);
}  // namespace core::dynamic::solver

#endif
