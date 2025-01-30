#include "system.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <filesystem>

namespace utils {
std::string GetDefaultPath() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    return std::filesystem::path(path).parent_path().string();
}
}  // namespace utils
