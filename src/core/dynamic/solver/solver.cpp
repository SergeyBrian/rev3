#include "solver.hpp"

#if __APPLE__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunknown-pragmas"
#pragma clang diagnostic ignored "-Wunused-parameter"
#endif

#include <triton/context.hpp>

#if __APPLE__
#pragma clang diagnostic pop
#endif

#include "../../../utils/logger.hpp"

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

std::string Solve(const Target *target,
                  const std::vector<static_analysis::CFGNode *> &path) {
    logger::Info("Searching for solution using symbolic execution");
    logger::Debug("Initializing triton context");

    triton::Context ctx;
    ctx.setArchitecture(triton::arch::ARCH_X86);
    ctx.setConcreteRegisterValue(ctx.registers.x86_ebp, 0x600000);

    (void)target;
    (void)path;

    logger::Error("Failed to find solution");
    return "";
}
}  // namespace core::dynamic::solver
