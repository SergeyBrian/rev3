#ifndef CORE_HPP
#define CORE_HPP

#include "../utils/errors.hpp"
#include "target.hpp"

namespace core {
Err Init();
void Run();
Target *GetActiveTarget();
}  // namespace core

#endif
