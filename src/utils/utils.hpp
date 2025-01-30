#ifndef UTILS_UTILS_HPP
#define UTILS_UTILS_HPP

namespace utils {
template <class C, typename T>
inline bool contains(C &&c, T e) {
    return find(begin(c), end(c), e) != end(c);
};
}  // namespace utils

#endif
