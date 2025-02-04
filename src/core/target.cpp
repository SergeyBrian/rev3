#include "target.hpp"

#include <filesystem>

namespace core {
Target::Target(const std::string &filename) : filename(filename) {
    std::filesystem::path path(filename);
    display_name = path.stem().string();
}
}  // namespace core
