#include "system.hpp"

#if _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#elif __APPLE__
#include <mach-o/dyld.h>
#endif

#include <filesystem>

namespace utils {
std::string GetDefaultPath() {
#if _WIN32
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
#else
    char path[1024];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);
#endif
    return std::filesystem::path(path).parent_path().string();
}
}  // namespace util
