#include "pre_checks.hpp"

#include <fstream>

#include "../utils/logger.hpp"

namespace pre_checks {
Err FileExists(const char *filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        logger::Error("Can't open file '%s'", filename);
        return Err::FileNotFound;
    }

    return Err::Ok;
}
}  // namespace pre_checks
