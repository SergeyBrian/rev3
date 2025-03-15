#ifndef UTILS_UTILS_HPP
#define UTILS_UTILS_HPP

#include <string>

#include "alias.hpp"
#define UNREACHABLE throw std::runtime_error("This branch should not execute");

namespace utils {
template <class C, typename T>
inline bool contains(C &&c, T e) {
    return find(begin(c), end(c), e) != end(c);
};

std::string UnescapeString(const std::string &str);

inline bool IsMSVCAligned(u64 address) {
    return (address % 4 == 0 || address % 16 == 0);
}
}  // namespace utils

#endif
