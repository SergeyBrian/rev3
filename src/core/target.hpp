#ifndef CORE_STATIC_FILE_HPP
#define CORE_STATIC_FILE_HPP

#include <string>

#include <LIEF/LIEF.hpp>

namespace core {
struct Target {
    std::string filename;
    std::string name;
    std::unique_ptr<LIEF::Binary> lief_info{};

    Target(const std::string &filename);
};
}  // namespace core

#endif
