#include "solver.hpp"

namespace core::dynamic::solver {
static const std::map<std::string, bool> ImportantFunctions{
    {"_security_init_cookie", false},
};

void CleanUpTrace(const Target *target,
                  std::vector<static_analysis::CFGNode *> &path) {
    for (auto it = path.begin(); it != path.end();) {
        auto node = *it;
        if (target->functions.contains(node->block.real_address)) {
            auto func = target->functions.at(node->block.real_address);
            if (ImportantFunctions.contains(func->display_name) &&
                !ImportantFunctions.at(func->display_name)) {
                it = path.erase(it);
                continue;
            }
        }
        it++;
    }
}
}  // namespace core::dynamic::solver
