#ifndef CORE_HPP
#define CORE_HPP

#include "../utils/errors.hpp"
#include "target.hpp"

namespace core {
Err Init();
void Run();
Target *GetActiveTarget();

void Inspect(const Target *target, u64 address);
void Info(const Target *target);
}  // namespace core

#endif
