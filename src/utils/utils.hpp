#ifndef UTILS_UTILS_HPP
#define UTILS_UTILS_HPP

#define UNREACHABLE assert(false && "This branch should never execute");

#include <string>

namespace utils {
template <class C, typename T>
inline bool contains(C &&c, T e) {
    return find(begin(c), end(c), e) != end(c);
};

std::string UnescapeString(const std::string &str);
}  // namespace utils

#endif
